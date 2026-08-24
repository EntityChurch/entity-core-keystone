"entity-core-protocol-smalltalk — the live-image LOAD script.

Pharo is a live-image system: 'load' = file-in each source doit into a running image, in
dependency order. Each src/*.st is a doit that installs its classes (Object << #Name
package: ...) and compiles their methods. This loader reads + evaluates each in order.

Run headless: pharo --headless <image> eval loads ONE doit. In practice the run scripts
build a peer image once (load + snapshot) so the classes are compile-time visible to the
test driver. The srcFiles list is the single source of truth for load order."

| base srcFiles |
base := FileLocator workingDirectory.
srcFiles := #(
	'src/EntityCore-Codec/EcErrors.st'
	'src/EntityCore-Codec/EcFloatBits.st'
	'src/EntityCore-Codec/EcCborEncoder.st'
	'src/EntityCore-Codec/EcValue.st'
	'src/EntityCore-Codec/EcCborDecoder.st'
	'src/EntityCore-Codec/EcVarint.st'
	'src/EntityCore-Codec/EcBase58.st'
	'src/EntityCore-Codec/EcPeerId.st'
	'src/EntityCore-Crypto/EcLibEntityCoreCodec.st'
	'src/EntityCore-Codec/EcContentHash.st'
	'src/EntityCore-Codec/EcConformance.st'
	"── S3 peer machinery (EntityCore-Peer, EntityCore-Capability). Load order honors
	   A-ST-010: a class must be installed before a later file references it by global name.
	   EcPeerErrors extends the S2 EntityCoreError tree; EcVal/EcEntity/EcEnvelope/EcIdentity/
	   EcWire/EcStore/EcNet/EcPending/EcHandlerContext supply the peer building blocks;
	   EcCapability is the L3 scaffold; EcPeer assembles them; EcPeerHandlers compiles the
	   built-in handlers onto the already-installed EcPeer. ──"
	'src/EntityCore-Peer/EcPeerErrors.st'
	'src/EntityCore-Peer/EcVal.st'
	'src/EntityCore-Peer/EcEntity.st'
	'src/EntityCore-Peer/EcEnvelope.st'
	'src/EntityCore-Peer/EcIdentity.st'
	'src/EntityCore-Peer/EcWire.st'
	'src/EntityCore-Peer/EcStore.st'
	'src/EntityCore-Peer/EcNet.st'
	'src/EntityCore-Peer/EcPending.st'
	'src/EntityCore-Peer/EcHandlerContext.st'
	'src/EntityCore-Peer/EcCoreTypes.st'
	'src/EntityCore-Capability/EcCapability.st'
	"── S4: the §5.5 chain verifier (needs EcCapability + EcIdentity + EcEntity, all above) ──"
	'src/EntityCore-Capability/EcCapAuthz.st'
	'src/EntityCore-Peer/EcPeer.st'
	'src/EntityCore-Peer/EcPeerHandlers.st'
	"── S4: the expanded handler surface + the §7a validate handlers (compiled onto EcPeer) ──"
	'src/EntityCore-Peer/EcPeerHandlers2.st'
	'src/EntityCore-Peer/EcValidate.st'
).
srcFiles do: [ :rel |
	Smalltalk compiler evaluate: (base / rel) contents ].
'entity-core-protocol-smalltalk loaded'
