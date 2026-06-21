"""S3 type-registry gate: every V7 §9.5 floor type rendered from the peer's OWN
model must reproduce the canonical content_hash (sha256 digest hex) byte-for-byte.

The expected hashes are the cross-blessed type-registry-vectors-v1 golden values
(the S8 drift target).  A divergence means a field shape (key set, optional flag,
carrier, layout) drifted from the floor.
"""

from __future__ import annotations

from entity_core.peer.typedefs import core_type_entities

# Expected content_hash (the 32-byte sha256 digest hex, after the 0x00 format
# byte) of each §9.5 floor type — the canonical type-registry-vectors-v1 golden.
FLOOR_TYPE_HASHES = {
    "primitive/any": "a004560007aac36b04c7af4be3c2bccd25cedb8b0a5aa87546aad284915e4268",
    "primitive/bool": "1557fd1ac85235584214bfd9a38c41491ac7ff300098014f9ab94cf73a9b8701",
    "primitive/bytes": "5044238b9e9fd06227da527366edf486ee52721ba7c4b4e197c818c24c091383",
    "primitive/float": "9d2e3fcb0885a46f2b3dc7873fffac11fbd09831b62d4f1c67d28859993e1088",
    "primitive/int": "eac87408aa4c42f5808409ec4ab39e32f5d3103216e0efe020f66d39c638db7f",
    "primitive/null": "65bf4034c5ea3b53e290bcac0cb106e4f200ea415a6da7f9f3fe1b1ee3a134a9",
    "primitive/string": "6bc8d94c120bc69edbbbb38dc7b6d27022fbd204e0a0e1962689e92f15253849",
    "primitive/uint": "659fb438153f98f9f7c5ab5e5e57c1d86a5e94b4bd5b50e9f08a0fb135c20c9e",
    "entity": "493669446020013dc15b78c55349765a6d39a797f584df617f48ab3c757d4bec",
    "core/entity": "fd0582910fa8e619da587ca133d69b63cb5db3efcdf7895c858b07f803262e89",
    "core/envelope": "27d7947fffe1a3b238c97fb38dc30054d5ee3685cf5e76e097588c01bab618f7",
    "system/envelope": "90525ea5c11bfbb7b7c7238593ac9b7c564600e17463a5e36c46294c7dee65a5",
    "system/protocol/envelope": "8112fdcbdeb0d7c79dd2972ddb688910830e8eba89d9a4de78fe66351a7e84b8",
    "system/hash": "cf4d3c3a47506f1229b640841e259862150eacefd432e6030bf77a4be2e6671f",
    "system/peer": "47772b56d50baa96b99e42cec8dc7d63a699f874ff1e710622c948e9ed2ff322",
    "system/peer-id": "1f12324501d421abaa53c39786526560b94ecded1c532bdbf42c322a1cc203e0",
    "system/signature": "a15f82c83279a6a982d236b4c848f62ba5af6e25f2379fa9b769eafd18047024",
    "system/protocol/connect/authenticate": "659b825342b5068724c02154fc8c1d3fac35bf2e54d9f9fe0061c057197746b8",
    "system/protocol/connect/hello": "5c107209cf62a6e3368dfd35bffe4a92efeb4c506d3be167ba1ff6a850e20620",
    "system/protocol/error": "5b20c13af577efe9205164e980858fee27f15a5884f15d1b6bb68b02f3179e5e",
    "system/protocol/execute": "71dd3207bb7b5506b903d608e6a4ce45ab66778eff623fa1fd07a8edb054da77",
    "system/protocol/execute/response": "abb33f5811fef22c2e8baeb96108374c2c38ccef80136814cbe5e004071a4eb5",
    "system/protocol/resource-target": "dcbda85691f9fe9c85421068f4697894169c6f1419da340093d6e2cd6d213ebe",
    "system/capability/grant": "fbfe941a08e468872bdb6fa88cd546dffca04381f3e2b87b4b101b3585f3a4f3",
    "system/capability/grant-entry": "2589e2924c1690352c431d426799f0207ab7a61116a7360cae441fd7e85aa86e",
    "system/capability/id-scope": "bd127df1776263903dacb7cc4abafccfc534890fe2dfef4e6ca538aed0605430",
    "system/capability/path-scope": "c0a10ccd0ce83fc26042fccd1f8323cc1235a36630b3a5dd8827233717f5705d",
    "system/capability/request": "ed632487bd13c3bd7d4fa1aab52c45c9392efc81784769f51d92d793d2eec8bc",
    "system/capability/revocation": "959ece5551c92f303fda84e8cf9025030eb0f9229e5f107e9d350fa898945584",
    "system/capability/revoke-request": "fc7e38519508a5545c68ec7d05f7bdfbff25937bd41a8841660a6fb8056d990c",
    "system/capability/delegate-request": "4bbde1cc47eeafb1c5dc5c5421d1575da6e4e776ef233505d55cee0a07228ef5",
    "system/capability/delegation-caveats": "21782403f0fd2200e91f4617b6131dededbb8791e579a271ac16697deb1af00c",
    "system/capability/policy-entry": "35b8798e8a3812ffb4da1c18e3d03efec618243304400008778ba4bd213bc4e7",
    "system/capability/token": "a5e7ebbd1d0064c309e54dc3b1cf8b65100ca0ce1635713702f1cb079d140d6b",
    "system/capability/multi-granter": "3b9cd006790e7ed5d8188c4382855e7e02712c7354afcc7da84f1a90c8304079",
    "system/handler": "dd2302c241b75a2f412b6208b0140782dcc1443280a27c27a5baa4d6c0919935",
    "system/handler/interface": "a8b9f03f9692f9b39a1040dd2139afcf8a49b3746719ae5681a1dbd32f7e621a",
    "system/handler/manifest": "cae7ff32dada03996aaf05682ef7413746606e7c31ba47e025e9c26d63f1e2e7",
    "system/handler/operation-spec": "60c6ae4d8e3291c0eba09b50a14c4679d6ed6204893fbedc4b6b0127a74dc32d",
    "system/handler/register-request": "6384eb7c00d06bd22a75191a65a2a0cd539990e1490603595ddb85a7f8ea913e",
    "system/handler/register-result": "f4e20788e43753f356539ffbddb17da196717f35d04f15505b1c398b77607b85",
    "system/tree/get-request": "f38687ad529b885e02c09cc90e9a79f861821b6fe2e9bcd4ba98dec6339039fb",
    "system/tree/put-request": "1eb650144f38ae6d47c05664f423ed81d237736f2b27c237132a1c4773af0634",
    "system/tree/listing": "c920fba05dbddf8df99175027dd07b1ee47879b7890ffd9add37569ebed435b1",
    "system/tree/listing-entry": "309bef6b57c8b3c0e70b85ca5d17736463a1e6f7c057d7d5d8e1f53aec3ca45f",
    "system/tree/path": "48ceb85457e159ffe9a04afe3aa4d499d134a7c2b15f24bb717d0425a2f99317",
    "system/type": "67868ab380a2c75bce6e9bbc3cd8578c209413033f4d0f6f85aee6607a3d791c",
    "system/type/field-spec": "e1bcd07acba25fd304df0638b5ddb4576304d2a50a14e7d8930693f5c1f2a8e6",
    "system/type/name": "4b09ba68d27307dbc28bdbf832d7b4a1320fc5f7eabd607b515f72a72e7a0862",
    "system/bounds": "cd0b0a87f5ce9ad61852eec0c842de30e55ffdf4fd472936827a4f3bb90e422d",
    "system/resource-limits": "a506c55bda1df601290c11700a2b6321f3032ec6f0dcbded64b82cfeda608bd1",
    "system/delivery-spec": "dd3caa625ef40c3527f8d8f528e4dcfe202a3c9833fac4408166785ac656a70c",
    "system/deletion-marker": "2a887a7ed8cf9c479c1f5038e4ea8aa39108e1b5cf5c7850dff857968c068dc0",
}


def test_core_type_registry_byte_identical():
    entities = core_type_entities()
    assert len(entities) == 53, f"core type floor = {len(entities)}, want 53"
    assert len(FLOOR_TYPE_HASHES) == 53

    seen = set()
    for name, e in entities:
        assert name in FLOOR_TYPE_HASHES, f"{name}: not in the floor hash table"
        seen.add(name)
        assert len(e.hash) == 33 and e.hash[0] == 0x00, f"{name}: bad framing {e.hash.hex()}"
        got = e.hash[1:].hex()
        want = FLOOR_TYPE_HASHES[name]
        assert got == want, f"{name}: content_hash mismatch\n  got  {got}\n  want {want}"

    missing = set(FLOOR_TYPE_HASHES) - seen
    assert not missing, f"floor types not rendered: {sorted(missing)}"
