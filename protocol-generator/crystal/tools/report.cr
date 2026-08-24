# Standalone breakdown printer (not a spec) — used by run-s2.sh / report gen to
# emit the per-category P/W/F/S counts for CONFORMANCE-REPORT.{md,json}.
require "../src/entity_core"

corpus = File.open(
  File.expand_path(File.join(__DIR__, "..", "..", "shared", "test-vectors", "v0.8.0", "conformance-vectors-v1.cbor")), "rb"
) do |f|
  s = Bytes.new(f.size)
  f.read_fully(s)
  s
end

results = EntityCore::Conformance.run(corpus)
by_cat = ::Hash(String, ::Hash(Symbol, Int32)).new
results.each do |r|
  cat = r.id.split(".").first
  by_cat[cat] ||= {:pass => 0, :fail => 0}
  by_cat[cat][r.status] = (by_cat[cat][r.status]? || 0) + 1
end

total_pass = results.count { |r| r.status == :pass }
puts "TOTAL #{total_pass}/#{results.size}"
by_cat.keys.sort.each do |cat|
  h = by_cat[cat]
  puts "  #{cat}: pass=#{h[:pass]? || 0} fail=#{h[:fail]? || 0}"
end
results.select { |r| r.status != :pass }.each do |r|
  puts "FAIL #{r.id}: #{r.detail}"
end
