// eslint-disable-next-line no-undef
const FileUpload = artifacts.require('contracts/FileUpload')

module.exports = function (deployer) {
  deployer.deploy(FileUpload)
}
