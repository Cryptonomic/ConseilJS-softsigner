const TerserPlugin = require('terser-webpack-plugin');
const path = require('path');
const TsConfigPathsPlugin = require('tsconfig-paths-webpack-plugin');
const { CheckerPlugin } = require('awesome-typescript-loader');

const webConfig = {
    mode: 'production',
    entry: './src/index.ts',
    target: 'web',
    output: {
        path: path.resolve(__dirname, './dist-web'),
        filename: 'conseiljs-softsigner.min.js',
        library: 'conseiljssoftsigner',
        libraryTarget: 'umd'
    },
    resolve: {
        extensions: ['.ts', '.tsx', '.js'],
        plugins: [
            new TsConfigPathsPlugin({
                configFile: './tsconfig.json'
            })
        ]
    },
    module: {
        rules: [
            { test: /\.tsx?$/, loader: 'awesome-typescript-loader' }
        ]
    },
    node: {
        
    },
    plugins: [new CheckerPlugin()],
    optimization: {
        minimizer: [new TerserPlugin()]
    }
};

module.exports = [webConfig];
