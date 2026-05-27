'use strict';

/**
 * Minimal linear algebra utilities for Bell's Inequality, quantum crypto,
 * and eigen-ethics systems. No external dependencies.
 */

const Matrix = {
  /** Dot product of two vectors */
  dot(a, b) {
    if (a.length !== b.length) throw new Error(`dot: dimension mismatch ${a.length} vs ${b.length}`);
    let sum = 0;
    for (let i = 0; i < a.length; i++) sum += a[i] * b[i];
    return sum;
  },

  /** Outer product: a ⊗ b → matrix */
  outer(a, b) {
    return a.map(ai => b.map(bj => ai * bj));
  },

  /** Matrix multiply: A (m×n) × B (n×p) → C (m×p) */
  multiply(A, B) {
    const m = A.length, n = A[0].length, p = B[0].length;
    const C = Array.from({ length: m }, () => new Array(p).fill(0));
    for (let i = 0; i < m; i++)
      for (let k = 0; k < n; k++)
        for (let j = 0; j < p; j++)
          C[i][j] += A[i][k] * B[k][j];
    return C;
  },

  /** Transpose: A (m×n) → A^T (n×m) */
  transpose(A) {
    const m = A.length, n = A[0].length;
    const T = Array.from({ length: n }, () => new Array(m));
    for (let i = 0; i < m; i++)
      for (let j = 0; j < n; j++)
        T[j][i] = A[i][j];
    return T;
  },

  /** Euclidean norm of a vector */
  norm(v) {
    return Math.sqrt(v.reduce((s, x) => s + x * x, 0));
  },

  /** Normalize a vector to unit length */
  normalize(v) {
    const n = Matrix.norm(v);
    return n > 1e-12 ? v.map(x => x / n) : v.slice();
  },

  /** Pearson correlation coefficient between two arrays */
  correlation(x, y) {
    const n = x.length;
    if (n !== y.length || n < 2) return 0;
    let sx = 0, sy = 0, sxx = 0, syy = 0, sxy = 0;
    for (let i = 0; i < n; i++) {
      sx += x[i]; sy += y[i];
      sxx += x[i] * x[i]; syy += y[i] * y[i];
      sxy += x[i] * y[i];
    }
    const num = n * sxy - sx * sy;
    const den = Math.sqrt((n * sxx - sx * sx) * (n * syy - sy * sy));
    return den > 1e-12 ? num / den : 0;
  },

  /** Covariance matrix from array-of-vectors data (each row is an observation) */
  covariance(data) {
    const n = data.length;
    const d = data[0].length;
    const means = new Array(d).fill(0);
    for (const row of data) for (let j = 0; j < d; j++) means[j] += row[j];
    for (let j = 0; j < d; j++) means[j] /= n;

    const cov = Array.from({ length: d }, () => new Array(d).fill(0));
    for (const row of data)
      for (let i = 0; i < d; i++)
        for (let j = 0; j < d; j++)
          cov[i][j] += (row[i] - means[i]) * (row[j] - means[j]);
    for (let i = 0; i < d; i++)
      for (let j = 0; j < d; j++)
        cov[i][j] /= (n - 1);
    return cov;
  },

  /** Jacobi eigenvalue algorithm for n×n symmetric matrix */
  jacobiEigenvalues(A, maxIter = 100) {
    const n = A.length;
    const D = A.map(r => r.slice());
    for (let iter = 0; iter < maxIter; iter++) {
      // Find largest off-diagonal element
      let p = 0, q = 1, maxVal = 0;
      for (let i = 0; i < n; i++)
        for (let j = i + 1; j < n; j++) {
          const v = Math.abs(D[i][j]);
          if (v > maxVal) { maxVal = v; p = i; q = j; }
        }
      if (maxVal < 1e-12) break;

      const theta = D[q][q] - D[p][p];
      const t = theta >= 0
        ? 2 * D[p][q] / (theta + Math.sqrt(theta * theta + 4 * D[p][q] * D[p][q]))
        : 2 * D[p][q] / (theta - Math.sqrt(theta * theta + 4 * D[p][q] * D[p][q]));
      const c = 1 / Math.sqrt(1 + t * t);
      const s = t * c;

      for (let i = 0; i < n; i++) {
        if (i !== p && i !== q) {
          const aip = D[i][p], aiq = D[i][q];
          D[i][p] = D[p][i] = c * aip - s * aiq;
          D[i][q] = D[q][i] = s * aip + c * aiq;
        }
      }
      const app = D[p][p], aqq = D[q][q], apq = D[p][q];
      D[p][p] = c * c * app - 2 * s * c * apq + s * s * aqq;
      D[q][q] = s * s * app + 2 * s * c * apq + c * c * aqq;
      D[p][q] = D[q][p] = 0;
    }
    return D.map((row, i) => row[i]).sort((a, b) => b - a);
  },

  /** Singular values via eigenvalues of A^T A */
  singularValues(A) {
    const At = Matrix.transpose(A);
    const AtA = Matrix.multiply(At, A);
    const eigenvalues = Matrix.jacobiEigenvalues(AtA);
    return eigenvalues.map(v => Math.sqrt(Math.max(0, v)));
  },

  /** Create identity matrix of size n */
  identity(n) {
    return Array.from({ length: n }, (_, i) =>
      Array.from({ length: n }, (_, j) => i === j ? 1 : 0)
    );
  },

  /** CHSH S-value: |E(a,b) - E(a,b') + E(a',b) + E(a',b')| using Pearson correlation */
  chshS(a, aPrime, b, bPrime) {
    const Eab   = Matrix.correlation(a, b);
    const EabP  = Matrix.correlation(a, bPrime);
    const EaPb  = Matrix.correlation(aPrime, b);
    const EaPbP = Matrix.correlation(aPrime, bPrime);
    return Math.abs(Eab - EabP + EaPb + EaPbP);
  }
};

module.exports = { Matrix };
