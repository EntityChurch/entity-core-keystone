{-# LANGUAGE OverloadedStrings #-}

-- | Standalone conformance runner: @cabal run conformance-exe@ prints a
-- per-category PASS/FAIL table for the v0.8.0 corpus (the self-contained S2 gate;
-- no live Go oracle needed). Exits non-zero on any failure.
module Main (main) where

import Control.Monad (forM, forM_)
import Data.List (sortOn)
import qualified Data.Text as T
import System.Environment (getArgs)
import System.Exit (exitFailure, exitSuccess)

import Fixture (Vector (..), loadVectors, runVector, vectorCategory)

main :: IO ()
main = do
  args <- getArgs
  let path = case args of
        (p : _) -> p
        [] -> "../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
  result <- loadVectors path
  case result of
    Left err -> putStrLn ("load failed: " ++ err) >> exitFailure
    Right vectors -> do
      outcomes <- forM vectors $ \v -> pure (v, runVector v)
      let total = length outcomes
          passes = length [() | (_, Right ()) <- outcomes]
          fails = [(v, r) | (v, Left r) <- outcomes]
      putStrLn "category        pass/total"
      forM_ (categorize outcomes) $ \(cat, p, t) ->
        putStrLn (pad 16 (T.unpack cat) ++ show p ++ "/" ++ show t)
      putStrLn "----------------"
      putStrLn ("TOTAL           " ++ show passes ++ "/" ++ show total)
      if null fails
        then putStrLn "RESULT: PASS" >> exitSuccess
        else do
          putStrLn "RESULT: FAIL"
          forM_ fails $ \(v, r) -> putStrLn ("  " ++ T.unpack (vId v) ++ ": " ++ r)
          exitFailure

categorize :: [(Vector, Either String ())] -> [(T.Text, Int, Int)]
categorize outcomes =
  let cats = sortOn id (uniq (map (vectorCategory . fst) outcomes))
   in [ (c, passN c, totalN c) | c <- cats ]
  where
    passN c = length [() | (v, Right ()) <- outcomes, vectorCategory v == c]
    totalN c = length [() | (v, _) <- outcomes, vectorCategory v == c]
    uniq = foldr (\x acc -> if x `elem` acc then acc else x : acc) []

pad :: Int -> String -> String
pad n s = s ++ replicate (max 0 (n - length s)) ' '
