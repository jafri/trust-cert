import { copyFileSync, accessSync, existsSync, readdirSync, lstat, readFileSync } from 'fs'
import { join, basename, extname } from 'path'
import { promisify } from 'util'
import which from 'async-which'
import { Certificate } from '@fidm/x509'
import { exec as sudoExec } from 'exec-root'
import { exec } from 'child_process'

const nonSudoExec = promisify(exec)
const lstatAsync = promisify(lstat)

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
const getCertCommonName = async (certPath: string) => {
  // Check cert exists
  accessSync(certPath)

  // Read file
  const cert = Certificate.fromPEM(readFileSync(certPath))
  return cert.issuer.commonName
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

  async exists(certPath: string): Promise<boolean> {
    return false
  }

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

  async installFromFile(certPath: string) {
    // Check cert exists
    accessSync(certPath)

    const { stderr } = await sudoExec(
      `security add-trusted-cert -d -k /Library/Keychains/System.keychain "${certPath}"`
    )

    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string) {
    const { stderr } = await sudoExec(
      `security delete-certificate -c "${await getCertCommonName(certPath)}"`
    )
    this.handleInstallResult(stderr, false)
  }

  async exists(certPath: string): Promise<boolean> {
    try {
      await nonSudoExec(
        `security find-certificate -c ${await getCertCommonName(
          certPath
        )} "/Library/Keychains/System.keychain"`
      )
      return true
    } catch (e) {
      return false
    }
  }
}

export class WindowsTrust extends Trust {
  name: string = 'Windows'

  async installFromFile(certPath: string) {
    // Check cert exists
    accessSync(certPath)

    // Copy over to .cer
    const newCertPath = this.convertPathToCer(certPath)

    // Copy cert to trust path
    copyFileSync(certPath, newCertPath)

    const { stderr } = await sudoExec(`certutil -addstore "Root" "${newCertPath}"`)

    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string) {
    const { stdout, stderr } = await nonSudoExec(`certutil.exe -dump "${certPath}" | find "Serial"`)

    if (stdout) {
      const [, , serialNumber] = stdout.split(' ')
      const { stderr } = await sudoExec(`certutil -delstore "Root" "${serialNumber.trim()}"`)
      this.handleInstallResult(stderr, false)
    } else {
      this.handleInstallResult(stderr, false)
    }
  }

  async exists(certPath: string): Promise<boolean> {
    try {
      const { stdout, stderr } = await nonSudoExec(`certutil.exe -verify "${certPath}"`)

      // ?
      if (stdout) {
        return !/UNTRUSTED root/.test(stdout)
        // Does not exist
      } else if (stderr) {
        return false
        // Exists
      } else {
        return true
      }
    } catch (e) {
      return false
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

  async installFromFile(certPath: string) {
    // Check cert exists and copy cert to trust path
    existsSync(certPath)
    copyFileSync(certPath, this.getNewCertPath(certPath))

    // Update trust store
    const { stderr } = await sudoExec(this.systemTrustCommands.join(' '))
    this.handleInstallResult(stderr, true)
  }

  async uninstall(certPath: string) {
    const { stderr } = await sudoExec(`rm -f ${this.getNewCertPath(certPath)}`)
    this.handleInstallResult(stderr, false)
  }

  async exists(certPath: string): Promise<boolean> {
    return isFile(this.getNewCertPath(certPath))
  }

  getNewCertPath(certPath: string): string {
    const certFileName = basename(certPath, extname(certPath))
    return this.systemTrustFilename.replace('%s', certFileName)
  }
}

export class NssTrust extends Trust {
  name: string = 'Nss'
  nssProfileDir: string = this.getNssProfileDir()
  certutilPath: string = this.getCertutilPath()

  async installFromFile(certPath: string) {
    for (const db of await this.getFirefoxDatabases()) {
      const { stderr } = await sudoExec(
        `${this.certutilPath} -A -d "${db}" -t C,, -n "${await getCertCommonName(
          certPath
        )}" -i "${certPath}"`
      )

      this.handleInstallResult(stderr, true)
    }
  }

  async uninstall(certPath: string) {
    for (const db of await this.getFirefoxDatabases()) {
      const { stderr } = await sudoExec(
        `${this.certutilPath} -D -d "${db}" -n "${await getCertCommonName(certPath)}"`
      )

      this.handleInstallResult(stderr, false)
    }
  }

  async exists(certPath: string): Promise<boolean> {
    let allExist = true

    for (const db of await this.getFirefoxDatabases()) {
      try {
        const { stdout, stderr } = await nonSudoExec(
          `${this.certutilPath} -V -d "${db}" -n "${await getCertCommonName(certPath)}" -u L`
        )
        console.log('Firefox exists stdout:', stdout)
        console.log('Firefox exists stderr:', stderr)
      } catch (e) {
        allExist = false
      }
    }

    return allExist
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
