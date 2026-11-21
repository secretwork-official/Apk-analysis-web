'use strict';
const { parentPort, workerData } = require('worker_threads');
const { analyzeApk, securityScore, grade, diffAnalyses } = require('./scan');

(async () => {
  try {
    if (workerData.op === 'diff') {
      const a = await analyzeApk(Buffer.from(workerData.bufA));
      const b = await analyzeApk(Buffer.from(workerData.bufB));
      parentPort.postMessage({ ok: true, result: diffAnalyses(a, b) });
    } else {
      const r = await analyzeApk(Buffer.from(workerData.buf));
      r.score = securityScore(r.vulnerabilities, r.secrets); r.grade = grade(r.score);
      if (r.certificate && r.certificate.error) delete r.certificate.error;
      parentPort.postMessage({ ok: true, result: r });
    }
  } catch (e) {
    parentPort.postMessage({ ok: false, error: String((e && e.message) || e) });
  }
})();
