import * as esbuild from 'esbuild';

const watch = process.argv.includes('--watch');

const config = {
  entryPoints: ['src/index.jsx'],
  bundle: true,
  minify: !watch,
  outfile: '../static/app.js',
  jsxFactory: 'h',
  jsxFragment: 'Fragment',
  define: {
    'process.env.NODE_ENV': watch ? '"development"' : '"production"',
  },
  loader: {
    '.jsx': 'jsx',
  },
};

if (watch) {
  const ctx = await esbuild.context(config);
  await ctx.watch();
  console.log('watching...');
} else {
  await esbuild.build(config);
  console.log('build complete');
}
