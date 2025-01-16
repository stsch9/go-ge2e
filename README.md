# go-ge2e

**WARNING**: This is just a PoC. Use at your own risk.

This is a simple encryption cli. In addition, all file names are saved with a random string of constant length.  Nevertheless, all file names stored in a directory (here called dataroom) can be listed. It is also possible to rotate the key pair of thee dataroom. An efficient update procedure renews the encrypted data so that this data can only be decrypted with the new key pair. The update can be done by an untrusted third party. A analogous procedure is used in [Updatable Oblivious Key Management for Storage Systems](https://eprint.iacr.org/2019/1275).

## How it works
### Dataroom creation
The user creates a dataroom directory `/PATH/TO/DATAROOM` and a  directory `/PATH/TO/DATAROOM/.meta` in which the file keys (for encrypting the file) and the file names are stored in encrypted form. In addition, a so-called dataroom ristretto255 key pair `(a, A)` is created, which is used to encrypt all data in the `.meta` directory:

The user creates a new file `Filekeys` with the content:

```
{
    "Version": 1,
    "Keys": {}
}
```
where `Version` is the version of the file and all filekeys are stored in `Keys`. For more details see below.

Then the user creates a random ristretto255 key pair `(e, E)` and calculates

```
shared_key = a * E
```

where * denotes the scalar multiplication over the elliptic curve ristretto255.
Then the user uses the HKDF function to create a symmetric key

```
k = hdkf(hash=sha256, secret=shared_key, salt=random(32), info=b'filekey')
```

Finally, the user encrypts the file Filekeys with `k`

```
Filekeys.enc = ascon(key=k, nonce=random(32), plaintext=Filekeys, ad=null)
```
and stores `Filekeys.enc` and `E` in `/PATH/TO/DATAROOM/.meta`.


### File upload to a dataroom
First, the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above).

Then the user creates a random filekey `fk` and a random(32) filename `fn` and stores this to `Filekeys`

```
{
    "Version": <VERSION> + 1,
    "Keys": {
        "<ACTUAL_FILENAME>": [fk, fn],
        ...
    }
}
```

The user encrypts the file with `fk`
```
fn = ascon(key=fk, nonce=random(32), plaintext=file, ad=null)
```
and stores the encrypted file with the name `fn` in `/PATH/TO/DATAROOM/fn`.

Finally, the user encrypts the file `Filekeys` with a new ephemaral public key `E` (see above) and stores `Filekeys.enc` and `E` in `/PATH/TO/DATAROOM/.meta`.

## List all files stored in the dataroom
The User the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above). This allows the user to query all file names that are listed in the Filekeys file and are therefore in the dataroom.

## File download
First, the user decrypts the file `Filekeys.enc` with the private dataroom key `a` and the ephemeral public `E` (see above).

The user then queries the filekey `fk` and the path to the encrypted file `fn` using the file filekeys.

The file can now be decrypted using the file path `fn` and the file key `fk`.

## Key Rotation

Suppose the user wants to renew the dataroom key `a`. He generates a new random ristretto255 dataroom key pair `(b, B)`. In addition, a so-called `factor` file is created, which contains the scalar product of the multiplicative inverse of `b` and `a`:

```
factor =  b^-1 * a (mod L)
```

where L is L the order of the ristretto255 group: (2^252 + 27742317777372353535851937790883648493).

The `factor` file is stored in the path `/PATH/TO/DATAROOM/.meta`.

## Rekey

The ephemeral public key `E` (stored in path `/PATH/TO/DATAROOM/.meta`) is multiplied by the `factor` generated during key rotation (see above):

```
F = factor * E
```
`E` is replaced by `F` in the path `/PATH/TO/DATAROOM/.meta`.

This allows the user to decrypt the file `Keyfiles.enc` with his new private key `b`, since the user receives the same `shared_key` as before:

```
b * F = b * (factor * E) = b * ((b^-1 * a) * E) = a * E = shared_key
```

Since neither the new private key `b` nor the old private key `a` can be calculated from the `factor`, the rekey operation can be executed by an untrusted third party.

## Usage
...