const Diff = require('diff');

function calculateDiff(original, modified) {
  const diff = Diff.diffLines(original, modified);
  return diff.map(part => ({
    value: part.value,
    added: part.added,
    removed: part.removed
  }));
}

module.exports = calculateDiff;