//this file specifies which babel transformations we're using
//  babel controls the transformation from javascript that we want to write (es7) into javascript that actually runs in browsers
module.exports = {
  presets: [
    "@babel/preset-env", //modern javascript features
  ],
  plugins: [
    "@babel/plugin-transform-runtime", //reduce utility duplication
    "@babel/plugin-proposal-object-rest-spread", //object spreading
  ],
};
