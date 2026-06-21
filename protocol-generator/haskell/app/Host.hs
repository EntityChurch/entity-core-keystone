{-# LANGUAGE OverloadedStrings #-}

-- | Standalone peer host — the runnable target for S4 conformance. Boots one
-- 'Peer' listener on a TCP port and blocks, so the entity-core-go @validate-peer@
-- oracle can drive the live wire surface. Twin of the C# @Host@, the TS @host.ts@,
-- and the OCaml @bin/host.ml@.
--
-- @
--   --port N               listen port (default 7777; 0 = auto-assign)
--   --name NAME            load a persistent Ed25519 identity from the standard
--                          on-disk location ~\/.entity\/peers\/NAME\/keypair (the
--                          entity-core PEM keypair: a base64-encoded 32-byte seed
--                          between BEGIN\/END ENTITY PRIVATE KEY lines — the same
--                          convention the Go entity-peer --name and peer-manager
--                          use). Without --name a fixed test seed is used.
--   --debug-open-grants    DEPRECATED (v7.74; removed v7.75): select the
--                          degenerate `default -> *` seed policy.
--   --seed-policy FILE     (next increment; A-HS-011) a seed-policy JSON file.
--   --validate             conformance build (GUIDE-CONFORMANCE §7a): register the
--                          system/validate/* test-handlers. OFF by default.
-- @
module Main (main) where

import Data.Bits (shiftL, shiftR, (.&.), (.|.))
import qualified Data.ByteString as B
import qualified Data.ByteString.Char8 as BC
import Data.Word (Word8)
import System.Environment (getArgs, lookupEnv)
import System.Exit (exitFailure, exitSuccess, exitWith, ExitCode (ExitFailure))
import System.IO (hPutStrLn, hSetBuffering, stderr, stdout, BufferMode (LineBuffering))
import System.IO.Error (catchIOError)
import qualified Data.Text as T

import EntityCore.Peer (Peer (..), createPeer)
import EntityCore.SeedPolicy (SeedPolicy (..))
import EntityCore.Transport (acceptLoop, listenOn)

-- | Fixed 32-byte Ed25519 seed → stable peer identity across runs (no --name).
defaultSeed :: BC.ByteString
defaultSeed = BC.replicate 32 '\x11'

-- | Decode standard-alphabet base64, ignoring whitespace and padding. Returns
-- 'Nothing' on an invalid character. Hand-rolled (no base64 package is available
-- in the sealed-offline store; depends only on bytestring, already a host dep).
b64Decode :: BC.ByteString -> Maybe B.ByteString
b64Decode = go 0 0 [] . BC.unpack
  where
    val :: Char -> Int
    val c
      | c >= 'A' && c <= 'Z' = fromEnum c - 65
      | c >= 'a' && c <= 'z' = fromEnum c - 71
      | c >= '0' && c <= '9' = fromEnum c + 4
      | c == '+' = 62
      | c == '/' = 63
      | otherwise = -1
    -- acc/bits accumulate sextets; emit a byte once >= 8 bits are buffered.
    go :: Int -> Int -> [Word8] -> [Char] -> Maybe B.ByteString
    go _ _ out [] = Just (B.pack (reverse out))
    go acc bits out (c : rest)
      | c `elem` (" \t\r\n=" :: String) = go acc bits out rest
      | v < 0 = Nothing
      | bits' >= 8 =
          let bits'' = bits' - 8
              byte = fromIntegral ((acc' `shiftR` bits'') .&. 0xff)
          in go acc' bits'' (byte : out) rest
      | otherwise = go acc' bits' out rest
      where
        v = val c
        acc' = (acc `shiftL` 6) .|. v
        bits' = bits + 6

-- | Load the 32-byte Ed25519 seed from the standard on-disk keypair (Go
-- entity-peer --name / peer-manager): ~\/.entity\/peers\/NAME\/keypair, a PEM
-- whose body is base64(seed) between BEGIN\/END ENTITY PRIVATE KEY lines.
loadSeedFromName :: String -> IO BC.ByteString
loadSeedFromName name = do
  home <- maybe "/root" id <$> lookupEnv "HOME"
  let path = home ++ "/.entity/peers/" ++ name ++ "/keypair"
  contents <-
    BC.readFile path `catchIOError` \e -> do
      hPutStrLn stderr ("error: --name " ++ name ++ ": " ++ show e)
      exitWith (ExitFailure 2)
  let body = BC.concat [l | l <- BC.lines contents, not (BC.isPrefixOf "-" l)]
  case b64Decode body of
    Just s | B.length s == 32 -> pure s
    Just s -> do
      hPutStrLn stderr
        ("error: --name " ++ name ++ ": expected a 32-byte seed, got "
          ++ show (B.length s) ++ " bytes")
      exitWith (ExitFailure 2)
    Nothing -> do
      hPutStrLn stderr ("error: --name " ++ name ++ ": malformed base64 keypair body")
      exitWith (ExitFailure 2)

data Opts = Opts {optPort :: Int, optOpen :: Bool, optValidate :: Bool, optSeed :: BC.ByteString}

parse :: [String] -> IO Opts
parse = go (Opts 7777 False False defaultSeed)
  where
    go o [] = pure o
    go o ("--port" : n : rest) = go o {optPort = read n} rest
    go o ("--name" : n : rest) = do
      s <- loadSeedFromName n
      go o {optSeed = s} rest
    go o ("--debug-open-grants" : rest) = do
      hPutStrLn stderr "warning: --debug-open-grants is DEPRECATED (v7.74 §6.9a; removed v7.75) — it now selects the degenerate `default -> *` seed policy. Prefer --seed-policy."
      go o {optOpen = True} rest
    go o ("--validate" : rest) = go o {optValidate = True} rest
    go _ (h : _) | h `elem` ["-h", "--help"] = do
      putStrLn "usage: host [--port N] [--name NAME] [--debug-open-grants] [--validate]"
      exitSuccess
    go _ (arg : _) = do
      hPutStrLn stderr ("error: unknown argument '" ++ arg ++ "'")
      exitFailure

main :: IO ()
main = do
  hSetBuffering stdout LineBuffering
  opts <- getArgs >>= parse
  let policy = if optOpen opts then SeedPolicyDebugOpen else SeedPolicyStandard
  peer <- createPeer (optSeed opts) policy (optValidate opts)
  (sock, bound) <- listenOn (optPort opts)
  putStrLn $
    "LISTENING 127.0.0.1:" ++ show bound
      ++ " peer_id="
      ++ T.unpack (peerLocal peer)
      ++ " open_grants="
      ++ show (optOpen opts)
      ++ " validate="
      ++ show (optValidate opts)
  acceptLoop peer sock
