import { MacOsTrust, WindowsTrust, LinuxTrust, NssTrust } from '../src/trust-cert'
import { join } from 'path'

const certPath = join(__dirname, '..', 'certs/eos_root_ca.crt')
const fakeCertPath = join(__dirname, '..', 'certs/eos_root_ca_fake.crt')

const generateTrust = () => {
  if (process.platform === 'darwin') {
    return new MacOsTrust()
  } else if (process.platform === 'win32') {
    return new WindowsTrust()
  } else if (process.platform === 'linux') {
    return new LinuxTrust()
  } else {
    throw new Error('Only MacOs, Linux and Windows supported')
  }
}

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
    const trust = new NssTrust()
    const installed = await trust.installFromFile(certPath)
    expect(installed).toBeTruthy()
  })
})
