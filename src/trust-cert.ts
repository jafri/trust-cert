import { copyFileSync, accessSync, existsSync, readdirSync, lstat, readFileSync } from 'fs'
import { join, basename, extname } from 'path'
import { promisify } from 'util'
import which from 'async-which'
import { exec as sudoExec } from 'exec-root'
import { exec } from 'child_process'
import { Certificate } from '@fidm/x509'

const nonSudoExec = promisify(exec)
const lstatAsync = promisify(lstat)
const DEFAULT_CERT_NAME = 'New Root CA'

const isDirectory = async (source: any) => {
  try {
    const stats = await lstatAsync(source)
    return stats.isDirectory()
  } catch (e) {
    return false
  }
}
const isFile = async (source: any) => {
  try {
    const stats = await lstatAsync(source)
    return stats.isFile()
  } catch (e) {
    return false
  }
}

export function generateTrust(platform: string = process.platform) {
  if (platform === 'darwin') {
    return new MacOsTrust()
  } else if (platform === 'win32') {
    return new WindowsTrust()
  } else if (platform === 'linux') {
    return new LinuxTrust()
  } else if (platform === 'nss') {
    return new NssTrust()
  } else {
    throw new Error('Only MacOs, Linux and Windows supported')
  }
}

export class Trust {
  name: string = ''

  handleInstallResult(stderr: string, adding: boolean) {
    if (stderr) {
      throw {
        message: `Could not ${adding ? 'add cert to' : 'remove cert from'} ${this.name} store`,
        err: stderr
      }
    } else {
      console.log(`Certificate successfully ${adding ? 'added to' : 'removed from'} ${this.name}!`)
      return true
    }
  }
}

export class MacOsTrust extends Trust {
  name: string = 'MacOs'

  async installFromFile(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    accessSync(certPath)

    const { stderr } = await sudoExec(
      `security add-trusted-cert -d -k /Library/Keychains/System.keychain "${certPath}"`
    )

    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    accessSync(certPath)
    const { stderr } = await sudoExec(`security remove-trusted-cert -d "${certPath}"`)
    this.handleInstallResult(stderr, false)
  }
}

export class WindowsTrust extends Trust {
  name: string = 'Windows'

  async installFromFile(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    accessSync(certPath)

    // Copy over to .cer
    const newCertPath = this.convertPathToCer(certPath)

    // Copy cert to trust path
    copyFileSync(certPath, newCertPath)

    const { stderr } = await sudoExec(`certutil -addstore "Root" "${newCertPath}"`)

    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    accessSync(certPath)

    // Read in cert
    const cert = Certificate.fromPEM(readFileSync(certPath))

    if (cert) {
      const { stdout, stderr } = await nonSudoExec(
        `certutil.exe -dump "${certPath}" | find "Serial"`
      )

      if (stdout) {
        const [, , serialNumber] = stdout.split(' ')
        const { stderr } = await sudoExec(`certutil -delstore "Root" "${serialNumber.trim()}"`)
        this.handleInstallResult(stderr, true)
      } else {
        this.handleInstallResult(stderr, true)
      }
    }
  }

  convertPathToCer(oldCertPath: string) {
    return oldCertPath.substr(0, oldCertPath.lastIndexOf('.')) + '.cer'
  }
}

export class LinuxTrust extends Trust {
  name: string = 'Linux'

  // SystemTrustFilename is the format used to name the root certificates.
  systemTrustFilename: string = ''

  // systemTrustCommands is the command used to update the system truststore.
  systemTrustCommands: string[] = []

  constructor() {
    super()

    if (existsSync('/etc/pki/ca-trust/source/anchors/')) {
      this.systemTrustFilename = '/etc/pki/ca-trust/source/anchors/%s.pem'
      this.systemTrustCommands = ['update-ca-trust', 'extract']
    } else if (existsSync('/usr/local/share/ca-certificates/')) {
      this.systemTrustFilename = '/usr/local/share/ca-certificates/%s.crt'
      this.systemTrustCommands = ['update-ca-certificates']
    } else if (existsSync('/etc/ca-certificates/trust-source/anchors/')) {
      this.systemTrustFilename = '/etc/ca-certificates/trust-source/anchors/%s.crt'
      this.systemTrustCommands = ['trust', 'extract-compat']
    }

    if (this.systemTrustCommands) {
      const resolved = which(this.systemTrustCommands[0])

      if (!resolved) {
        this.systemTrustCommands = []
      }
    }
  }

  async installFromFile(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    existsSync(certPath)

    // Change file name
    const certFileName = basename(certPath, extname(certPath))
    const newCertPath = this.systemTrustFilename.replace('%s', certFileName)

    // Copy cert to trust path
    copyFileSync(certPath, newCertPath)

    // Update trust store
    const { stderr } = await sudoExec(this.systemTrustCommands.join(' '))

    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Change file name
    const certFileName = basename(certPath, extname(certPath))
    const newCertPath = this.systemTrustFilename.replace('%s', certFileName)

    // Delete
    const { stderr } = await sudoExec(`rm -f ${newCertPath}`)

    this.handleInstallResult(stderr, false)
  }
}

export class NssTrust extends Trust {
  name: string = 'Nss'
  nssProfileDir: string = this.getNssProfileDir()
  certutilPath: string = this.getCertutilPath()

  async installFromFile(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    // Check cert exists
    accessSync(certPath)

    for (const db of await this.getFirefoxDatabases()) {
      const { stderr } = await sudoExec(
        `${this.certutilPath} -A -d "${db}" -t C,, -n "${certName}" -i "${certPath}"`
      )

      this.handleInstallResult(stderr, true)
    }
  }

  async uninstall(certPath: string, certName: string = DEFAULT_CERT_NAME) {
    for (const db of await this.getFirefoxDatabases()) {
      const { stderr } = await sudoExec(`${this.certutilPath} -D -d "${db}" -n "${certName}"`)

      this.handleInstallResult(stderr, false)
    }
  }

  async getFirefoxDatabases() {
    // Get all user profiles
    const profiles = readdirSync(this.nssProfileDir).map(profile =>
      join(this.nssProfileDir, profile)
    )

    let profileDirs = []
    for (const profile of profiles) {
      if (await isDirectory(profile)) {
        profileDirs.push(profile)
      }
    }

    // If any directories
    if (profileDirs.length) {
      let dbLinks = []
      for (const profile of profileDirs) {
        if (await isFile(join(profile, 'cert9.db'))) {
          dbLinks.push(`sql:${profile}`)
        } else if (await isFile(join(profile, 'cert8.db'))) {
          dbLinks.push(`dbm:${profile}`)
        }
      }

      return dbLinks
    } else {
      throw new Error('No profiles with cert8 or cert9 dbs found in firefox directory.')
    }
  }

  getNssProfileDir(): string {
    if (process.platform === 'win32') {
      return process.env['USERPROFILE'] + '\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles'
    } else if (process.platform === 'darwin') {
      return process.env['HOME'] + '/Library/Application Support/Firefox/Profiles/'
    } else if (process.platform === 'linux') {
      return process.env['HOME'] + '/.mozilla/firefox/'
    } else {
      return ''
    }
  }

  getCertutilPath(): string {
    if (process.platform === 'win32') {
      if (process.arch === 'x64') {
        return join(__dirname, '..', 'nss', 'win64', 'certutil.exe')
        // ia32
      } else {
        return join(__dirname, '..', 'nss', 'win32', 'certutil.exe')
      }
    } else if (process.platform === 'darwin') {
      return join(__dirname, '..', 'nss', 'mac', 'certutil')
    } else if (process.platform === 'linux') {
      if (process.arch === 'x64') {
        return join(__dirname, '..', 'nss', 'linux64', 'certutil')
      } else {
        return join(__dirname, '..', 'nss', 'linux32', 'certutil')
      }
    } else {
      throw new Error('NSS only supported on MacOs, Linux and Windows')
    }
  }
}
