const ExtractTextPlugin = require('extract-text-webpack-plugin')
const ClosureCompilerPlugin = require('webpack-closure-compiler')
const path = require('path')
module.exports = {
  entry: [
    './js/main.js', './web/css/custom.scss'
  ],
  devtool: 'source-map',
  module: {
    rules: [
      {
        test: /\.scss$/,
        loader: ExtractTextPlugin.extract({
          use: [
            {
              loader: 'css-loader',
              options: {}
            },
            {
              loader: 'sass-loader',
              options: {
                sourceMap: false
              }
            },
            {
              loader: 'postcss-loader',
              options: {
                'autoprefixer': {
                  browsers: ['last 2 versions', '> 5%'],
                  sourceMap: true
                }
              }
            }
          ]
        })
      }, {
        test: /\.(?:pug|jade)$/,
        loader: 'pug-loader'
      },
      {
        test: /\.(gif|jpeg|png|woff|woff2|eot|ttf|svg)$/,
        loader: 'file-loader',
        options: {
          outputPath: 'assets/',
          publicPath: '/'
        }
      }
    ]
  },
  plugins: [
    new ExtractTextPlugin({filename: '../build/css/[name].bundle.css'}),
    new ClosureCompilerPlugin({
      compiler: {
        language_in: 'ECMASCRIPT6',
        language_out: 'ECMASCRIPT3',
        compilation_level: 'SIMPLE',
        create_source_map: '[name]-' + (new Date())
      },
      concurrency: 3
    })
  ],
  resolve: {
    'alias': {
      'views': path.resolve(__dirname, 'views/')
    }
  },
  output: {
    path: path.join(__dirname, 'build'),
    filename: './js/bundle.js'
  }
}
