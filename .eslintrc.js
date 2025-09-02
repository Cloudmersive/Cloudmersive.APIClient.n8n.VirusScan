// .eslintrc.js
module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    plugins: ['@typescript-eslint', 'n8n-nodes-base'],
    extends: ['plugin:n8n-nodes-base/nodes', 'plugin:@typescript-eslint/recommended'],
    ignorePatterns: ['dist/**', 'node_modules/**'],
  };
  