# Changelog

## [1.32.18](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.17...v1.32.18) (2024-10-28)


### Bug Fixes

* **config:** DO not assume that gelf config is set ([62b7eb7](https://github.com/nodemailer/zonemta-wildduck/commit/62b7eb79efe0c2d43fcdf82ea3e24c56d82f6a3f))

## [1.32.17](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.16...v1.32.17) (2024-10-28)


### Bug Fixes

* **cicd-pipeline:** Add pipeline for building and pushing the docker image to GHCR ([1f4eeb4](https://github.com/nodemailer/zonemta-wildduck/commit/1f4eeb438249fbdaaed8cf17e87fe5ab3f777f56))
* **gelf-subject:** Set default subject limit in gelf logs ZMS-177 ([#32](https://github.com/nodemailer/zonemta-wildduck/issues/32)) ([36cc6af](https://github.com/nodemailer/zonemta-wildduck/commit/36cc6af74d3e63fb74d927a48141813b53de71a2))
* **license-readme:** ZMS-180 ([#33](https://github.com/nodemailer/zonemta-wildduck/issues/33)) ([81c4c7e](https://github.com/nodemailer/zonemta-wildduck/commit/81c4c7e70e568aa6d4cdf496cdcd534d648ab3a2))

## [1.32.16](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.15...v1.32.16) (2024-08-08)


### Bug Fixes

* bumped deps ([52392da](https://github.com/nodemailer/zonemta-wildduck/commit/52392dab2700769bc72110fd07b6f2716ece7807))

## [1.32.15](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.14...v1.32.15) (2024-05-02)


### Bug Fixes

* **deps:** Bumped deps ([6b4f2a4](https://github.com/nodemailer/zonemta-wildduck/commit/6b4f2a4869f02cd58149f3d6b3aa4962442c953a))

## [1.32.14](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.13...v1.32.14) (2024-04-29)


### Bug Fixes

* **SNI:** Autogenerate SNI certificate if needed ([1b18377](https://github.com/nodemailer/zonemta-wildduck/commit/1b183773fb7b1785ce5edbe3cb064e3b01d60679))

## [1.32.13](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.12...v1.32.13) (2024-04-22)


### Bug Fixes

* **deps:** Bumped deps ([c613418](https://github.com/nodemailer/zonemta-wildduck/commit/c61341828f36ffac324e2626896dca7cc81b42dd))

## [1.32.12](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.11...v1.32.12) (2024-04-01)


### Bug Fixes

* **deps:** Bumped wildduck from 1.42.1 to 1.42.5 ([4100aa0](https://github.com/nodemailer/zonemta-wildduck/commit/4100aa05286c368528373cb90694768260116302))

## [1.32.11](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.10...v1.32.11) (2024-02-09)


### Bug Fixes

* **logs:** log bounce events to graylog ([b3b8773](https://github.com/nodemailer/zonemta-wildduck/commit/b3b8773584eb58482c00b9355ae4664a53bb583e))

## [1.32.10](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.9...v1.32.10) (2024-02-08)


### Bug Fixes

* **logs:** log matches in queue poll entry ([84bf40b](https://github.com/nodemailer/zonemta-wildduck/commit/84bf40b9df26b6aad237f62c529198861cdd0937))

## [1.32.9](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.8...v1.32.9) (2024-02-08)


### Bug Fixes

* **logs:** log queue polling ([5c92731](https://github.com/nodemailer/zonemta-wildduck/commit/5c9273164189ea66c0bd67add7eccdf439883258))

## [1.32.8](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.7...v1.32.8) (2024-02-08)


### Bug Fixes

* **deps:** bumped wildduck version ([463d74a](https://github.com/nodemailer/zonemta-wildduck/commit/463d74ad6edc25d06d9d1a58d2108dc44e8f6f10))

## [1.32.7](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.6...v1.32.7) (2024-02-05)


### Bug Fixes

* **deps:** Bumped deps for fixes ([c656fe0](https://github.com/nodemailer/zonemta-wildduck/commit/c656fe0b87525cca5a808f4c2e45cf9af55eed32))

## [1.32.6](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.5...v1.32.6) (2023-12-14)


### Bug Fixes

* **defer:** Apply const:sender:defer_times for failed delivery attempts ([7d24a84](https://github.com/nodemailer/zonemta-wildduck/commit/7d24a84869309920b71a0df7a0ab34f684c3b75c))

## [1.32.5](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.4...v1.32.5) (2023-10-17)


### Bug Fixes

* **deps:** Bumped dependencies ([4c29efe](https://github.com/nodemailer/zonemta-wildduck/commit/4c29efefd1f41a8f639cb55cddf5525d33aaf0a4))

## [1.32.4](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.3...v1.32.4) (2023-09-05)


### Bug Fixes

* **release:** Added missing repo url to package.json ([57fb9dc](https://github.com/nodemailer/zonemta-wildduck/commit/57fb9dcbbb14bf81627eb2c3acc11e83cfe6e55a))

## [1.32.3](https://github.com/nodemailer/zonemta-wildduck/compare/v1.32.2...v1.32.3) (2023-09-05)


### Bug Fixes

* **tests:** fixed failing test ([5f758b5](https://github.com/nodemailer/zonemta-wildduck/commit/5f758b5c4bd3187c9cb7fbbe7ff7c9db67cae999))
