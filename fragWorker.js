// ============================================================
//  fragWorker.js  —  VENDOSE TE ROOT-i i backend-it (prane index.js)
//  Worker thread qe konverton IFC -> Fragments pa bllokuar serverin.
//  Shkarkon IFC nga R2, e konverton me That Open IfcImporter,
//  ngarkon .frag te R2, dhe i kthen rezultatin proceset kryesor.
// ============================================================

const { parentPort, workerData } = require('worker_threads');
const path = require('path');
const { S3Client, GetObjectCommand, PutObjectCommand } = require('@aws-sdk/client-s3');

async function streamToBuffer(stream) {
    const chunks = [];
    for await (const chunk of stream) chunks.push(chunk);
    return Buffer.concat(chunks);
}

(async () => {
    try {
        const { fileId, ifcR2Key } = workerData;

        const s3 = new S3Client({
            endpoint: 'https://' + process.env.B2_ENDPOINT,
            region: 'auto',
            credentials: {
                accessKeyId: process.env.B2_KEY_ID,
                secretAccessKey: process.env.B2_APPLICATION_KEY
            }
        });

        // 1) Shkarko IFC-ne nga R2
        const obj = await s3.send(new GetObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: ifcR2Key
        }));
        const ifcBuffer = await streamToBuffer(obj.Body);

        // 2) Konverto IFC -> Fragments (dynamic import sepse @thatopen/fragments eshte ESM)
        const fragments = await import('@thatopen/fragments');
        const IfcImporter = fragments.IfcImporter;

        const serializer = new IfcImporter();
        // web-ifc WASM: rrenja e paketes web-ifc ne node_modules
        const webIfcDir = path.dirname(require.resolve('web-ifc')) + path.sep;
        serializer.wasm = { absolute: true, path: webIfcDir };

        const fragBytes = await serializer.process({
            bytes: new Uint8Array(ifcBuffer)
        });

        // 3) Ngarko .frag te R2
        const fragKey = `web-frag/file-${fileId}/model.frag`;
        await s3.send(new PutObjectCommand({
            Bucket: process.env.B2_BUCKET_NAME,
            Key: fragKey,
            Body: Buffer.from(fragBytes),
            ContentType: 'application/octet-stream'
        }));

        parentPort.postMessage({ ok: true, fragKey });
    } catch (err) {
        parentPort.postMessage({ ok: false, error: (err && err.message) ? err.message : String(err) });
    }
})();
