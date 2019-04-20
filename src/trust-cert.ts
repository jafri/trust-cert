import { copyFileSync, accessSync, existsSync, readdirSync, lstatSync } from 'fs'
import { join, basename, extname } from 'path'
import { promisify } from 'util'
import which from 'which'
import { exec } from 'exec-root'

const sudoExec = promisify(exec)
const isDirectory = (source: any) => lstatSync(source).isDirectory()
const isFile = (source: any) => lstatSync(source).isFile()

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

  handleInstallResult(stderr: string) {
    if (stderr) {
      throw {
        message: `Could not add cert to ${this.name} store`,
        err: stderr
      }
    } else {
      console.log(`Certificate successfully added to ${this.name}!`)
      return true
    }
  }
}

export class MacOsTrust extends Trust {
  name: string = 'MacOs'

  async installFromFile(certPath: string, certName: string = 'New Root CA') {
    // Check cert exists
    accessSync(certPath)

    const { stderr } = await sudoExec(
      `security add-trusted-cert -d -k /Library/Keychains/System.keychain ${certPath}`
    )

    return this.handleInstallResult(stderr)
  }
}

export class NssTrust extends Trust {
  name: string = 'Nss'
  nssProfileDir: string = this.getNssProfileDir()
  certutilPath: string = this.getCertutilPath()

  async installFromFile(certPath: string, certName: string = 'New Root CA') {
    // Check cert exists
    accessSync(certPath)

    // Get all user profiles
    const profiles = readdirSync(this.nssProfileDir)
      .map(profile => join(this.nssProfileDir, profile))
      .filter(profile => isDirectory(profile))

    // If profiles
    if (profiles.length) {
      let dbLinks = []
      for (const profile of profiles) {
        if (isFile(join(profile, 'cert9.db'))) {
          dbLinks.push(`sql:${profile}`)
        } else if (isFile(join(profile, 'cert8.db'))) {
          dbLinks.push(`dbm:${profile}`)
        }
      }

      for (const db of dbLinks) {
        const { stderr } = await sudoExec(
          `${this.certutilPath} -A -d "${db}" -t C,, -n "${certName}" -i "${certPath}"`
        )

        this.handleInstallResult(stderr)
      }

      return true
    } else {
      return false
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
      if (process.arch === 'x32') {
        return join(__dirname, '..', 'nss', 'win32', 'certutil.exe')
      } else {
        return join(__dirname, '..', 'nss', 'win64', 'certutil.exe')
      }
    } else if (process.platform === 'darwin') {
      return join(__dirname, '..', 'nss', 'mac', 'certutil')
    } else if (process.platform === 'linux') {
      if (process.arch === 'x32') {
        return join(__dirname, '..', 'nss', 'linux32', 'certutil')
      } else {
        return join(__dirname, '..', 'nss', 'linux64', 'certutil')
      }
    } else {
      throw new Error('NSS only supported on MacOs, Linux and Windows')
    }
  }
}

export class WindowsTrust extends Trust {
  name: string = 'Windows'

  async installFromFile(certPath: string, certName: string = 'New Root CA') {
    // Check cert exists
    accessSync(certPath)

    // Copy over to .cer
    const newCertPath = certPath.substr(0, certPath.lastIndexOf('.')) + '.cer'

    // Copy cert to trust path
    copyFileSync(certPath, newCertPath)

    const { stderr } = await sudoExec(`certutil -addstore "Root" "${newCertPath}"`)

    return this.handleInstallResult(stderr)
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
      let resolved = which.sync(this.systemTrustCommands[0], { nothrow: true })

      if (!resolved) {
        this.systemTrustCommands = []
      }
    }
  }

  async installFromFile(certPath: string, certName: string = 'New Root CA') {
    // Check cert exists
    existsSync(certPath)

    // Change file name
    const certFileName = basename(certPath, extname(certPath))
    const newCertPath = this.systemTrustFilename.replace('%s', certFileName)

    // Copy cert to trust path
    copyFileSync(certPath, newCertPath)

    // Update trust store
    const { stderr } = await sudoExec(this.systemTrustCommands.join(' '))

    return this.handleInstallResult(stderr)
  }
}
