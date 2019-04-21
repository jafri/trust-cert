import { generateTrust } from '../src/trust-cert'
import { join } from 'path'

const sleep = require('util').promisify(setTimeout)

const certPath = join(__dirname, '..', 'certs/eos_root_ca.crt')
const fakeCertPath = join(__dirname, '..', 'certs/eos_root_ca_fake.crt')

/**
 * Full test
 */
describe('Full Platform Test', () => {
  it('Matches supported platforms', () => {
    console.log(process.platform)
    console.log(process.arch)
    const supported =
      process.platform === 'darwin' || process.platform === 'linux' || process.platform === 'win32'
    expect(supported).toBeTruthy()
  })

  it('Installs test root cert', async () => {
    let trust = generateTrust()
    await trust.installFromFile(certPath)
    await sleep(5000)
  }, 10000)

  it('Confirm installed cert', async () => {
    let trust = generateTrust()
    const exists = await trust.exists(certPath)
    expect(exists).toBeTruthy()
  }, 10000)

  it('Uninstalls test root cert', async () => {
    let trust = generateTrust()
    await trust.uninstall(certPath)
    await sleep(2000)
  }, 10000)

  it('Confirm uninstalled cert', async () => {
    let trust = generateTrust()
    const exists = await trust.exists(certPath)
    expect(exists).toBeFalsy()
  }, 10000)

  it('Fails on non existent cert', async () => {
    const trust = generateTrust()
    await expect(trust.installFromFile(fakeCertPath)).rejects.toThrow()
  })
})

describe('Full Firefox Test', () => {
  it('Installs Firefox Cert', async () => {
    const trust = generateTrust('nss')
    await trust.installFromFile(certPath)
  }, 10000)

  it('Confirm installed firefox cert', async () => {
    const trust = generateTrust('nss')
    const exists = await trust.exists(certPath)
    expect(exists).toBeTruthy()
  }, 10000)

  it('Uninstalls Firefox Cert', async () => {
    const trust = generateTrust('nss')
    await trust.uninstall(certPath)
  }, 10000)

  it('Confirm uninstalled firefox cert', async () => {
    const trust = generateTrust('nss')
    const exists = await trust.exists(certPath)
    expect(exists).toBeFalsy()
  }, 10000)
})
