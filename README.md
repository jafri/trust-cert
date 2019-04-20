# Trust Root Certificates in MacOs, Linux and Windows

### Installation
NPM
```
npm i trust-cert
```

Yarn
```
yarn add trust-cert
```

### Auto detect platform
```js
import { generateTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = generateTrust()

(async () => {
    await trust.installFromFile(certPath)
})
```

### MacOs
```js
import { MacOsTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new MacOsTrust()

(async () => {
    await trust.installFromFile(certPath)
})
```


### Linux
```js
import { LinuxTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new LinuxTrust()

(async () => {
    await trust.installFromFile(certPath)
})
```

### Windows
```js
import { WindowsTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new WindowsTrust()

(async () => {
    await trust.installFromFile(certPath)
})
```

### NSS (Cross-platform firefox)
Firefox does not use system store, so we package cross-platform nss binaries.

```js
import { NssTrust } from 'trust-cert'
import { join } from 'path'

const certPath = join(__dirname, 'certs/eos_root_ca.crt')
const trust = new NssTrust()

(async () => {
    await trust.installFromFile(certPath)
})
```

Note: The tests install the root CA in the certs folder into your store, modify the certs folder if you wish to test with your own cert.