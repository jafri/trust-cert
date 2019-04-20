import { generateTrust } from '../src/trust-cert'
import { join } from 'path'

const certPath = join(__dirname, '..', 'certs/eos_root_ca.crt')
const fakeCertPath = join(__dirname, '..', 'certs/eos_root_ca_fake.crt')

/**
 * Full test
 */
describe('Full Test', () => {
  it('Installs test root cert', async () => {
    let trust = generateTrust()
    const installed = await trust.installFromFile(certPath)
    expect(installed).toBeTruthy()
  })

  it('Fails on non existent cert', async () => {
    const trust = generateTrust()
    await expect(trust.installFromFile(fakeCertPath)).rejects.toThrow()
  })

  it('Firefox Cert', async () => {
    const trust = generateTrust('nss')
    const installed = await trust.installFromFile(certPath)
    expect(installed).toBeTruthy()
  })
})
