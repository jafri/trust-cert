import { generateTrust } from '../src/trust-cert'
import { join } from 'path'

const certPath = join(__dirname, '..', 'certs/eos_root_ca.crt')
const fakeCertPath = join(__dirname, '..', 'certs/eos_root_ca_fake.crt')

/**
 * Full test
 */
describe('Full Test', () => {
  it('Matches supported platforms', () => {
    console.log(process.platform)
    console.log(process.arch)
    const supported =
      process.platform === 'darwin' || process.platform === 'linux' || process.platform === 'win32'
    expect(supported).toBeTruthy()
  })

  it('Installs test root cert', async () => {
    let trust = generateTrust()
    await trust.installFromFile(certPath, 'EOS Root CA')
  }, 10000)

  it('Uninstalls test root cert', async () => {
    let trust = generateTrust()
    await trust.uninstall(certPath, 'EOS Root CA')
  }, 10000)

  it('Fails on non existent cert', async () => {
    const trust = generateTrust()
    await expect(trust.installFromFile(fakeCertPath)).rejects.toThrow()
  })

  it('Installs Firefox Cert', async () => {
    const trust = generateTrust('nss')
    await trust.installFromFile(certPath, 'EOS Root CA')
  }, 10000)

  it('Uninstalls Firefox Cert', async () => {
    const trust = generateTrust('nss')
    await trust.uninstall(certPath, 'EOS Root CA')
  }, 10000)
})
