# VaxMe Backend

[![Build](https://github.com/vax-me/vaccine-passport-be/actions/workflows/go.yml/badge.svg)](https://github.com/vax-me/vaccine-passport-be/actions/workflows/go.yml)

[![Publish Docker image](https://github.com/vax-me/vaccine-passport-be/actions/workflows/build-push-action.yml/badge.svg)](https://github.com/vax-me/vaccine-passport-be/actions/workflows/build-push-action.yml)

## A vaccine passport with privacy by design

VaxMe enables users to enjoy the freedom of vaccine passports without having an entity spying on them. 

Let us explain how it works:
1. Users request a passport
2. A doctor validates the passport
3. The user retrieves the passport
4. Anyone can validate the user's passport when scanning their QR Code

Appendix:

A. Doctor registration\
B. Invalidation

To see how we ensure you data stays private and how we avoid metadata hell, please read on:

### 1. User requests a passport
When users request a passport, their personal details without affiliation to any specific vaccine are stored on the server.
Furthermore, the user attaches an RSA public key that will be used to encrypt sensitive information (see 2.). 
This private/public key-pair is generated on device by the user in [the app](http://github.com/vax-me/vaccine-passport-app) and the private key will never leave the device.

All the above communication will be encrypted through TLS.

Therefore, the last threat model that is still left to consider is a malicious actor with database access.
Even with this knowledge, they could only see someone with a given name has requested a passport but not for which vaccine. 
Vaccine details are only entered by the doctor.

### 2. A doctor validates the passport
The doctor will be to request the backend to sign the passport. 
Doctors have to authenticate to the app.
Since authentication is a critical subject in our design, we outsourced the handling to Auth0, one of the leading providers with frequent audits, HIPPA/GDPR compliance and with millions of users trusting them.
Once logged in the doctor will validate that the patient's name and then proceed to enter dose information. 
Once received this information will be signed using the system's root certificated and immediately encrypted using the user's private key.
At no point will personal information linking someone to a vaccine be persisted in an unencrypted way.

### 3. The user retrieves the passport
Once the doctor has signed the passport, the user can retrieve the passport and decrypt in on their device.
The decrypted passport is then stored on-device and a QR-code for others to scan will be shown.

### 4. Anyone can validate the user's passport when scanning their QR Code
With the passport on device, any other VaxMe user can validate the passport by checking the signature against our root public key.
The reason we use the design of having one key is that we have a couple advantages:
1. Users can use the app offline - no need to update a list of doctors that are allowed to sign
2. No metadata will be created
The important fact to note here is that only the owner of the passport and the scanner can see the passport, containing name and dose information.
This means that the scanner will see private data but this is and inherent and acceptable risk since we need a way for anyone to validate passports.
It is imperative though that secondary ID should be used to validate the vaccine passport's owner's identity.
   
### A. Doctor registration
Doctors can be registered by local health authorities, governments or other ways. 
We understand the heterogeneous nature of this process and hence merely provide an API for ''super-users'' to assign doctor privileges.

### B. Invalidation
If a doctor's account is compromized, we need a way to revoke their passports.
Since our app is offline by design, this is accomplished by syncing a list of invalid passports every time an internet connection is available.
Super-users can revoke a doctor's signatures and update the list.
This case is likely the strongest for giving doctor's individual keys for signing instead of using a central root key.
We can see that this wouldn't in-fact solve issues: Besides the fact that valid keys must be synced which would not allow always-offline users to validate, revocations still  need to be synced.
Therefore, while the offline design means that potentially revoked passports can be validated, we have a mechanism for users to prevent this abuse, and we assume that users will connect to the internet from time to time.
The offline scenario is more likely to be transient, when for example in area of bad service or in case of a server outage.

## How to use

Likely it is most sensible to use our docker image `vaxmexyz/vaccine-passport-be`

For a quick and dirty deployment he `docker-compose.yml` will do but this is anything but production ready - so be warned.

When using said image you need to provide the following environment variables

Variable | Value
------------ | -------------
VaccinePassportPrivateKey | Path to an RSA private key file used as the root key
VaccinePassportMongoUrl | The url to the mongo db (format: `mongodb://user:pass@host:port`)
VaccinePassportAuthAud | The url on which your service is reachable must be registered in your auth0 api config
VaccinePassportSUEmail | The email of the initial super user
VaccinePassportAuthIss | The url of your auth0 space

## Creators

- [Adrian Lehmann](https://github.com/adrianleh)
- [Sebastian Markgraf](https://github.com/sebimarkgraf)