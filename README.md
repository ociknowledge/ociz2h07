# OCI Zero To Hero Chapter 7
Ejemplo desarrollado en NodeJS para mostrar el uso de autenticación con el IAM en OCI. Estos comandos están realizados para distribuciones Oracle Linux 8.

## Prerrequisitos
Es importante realizar el siguiente [Luna Lab](https://luna.oracle.com/lab/45ae3588-3dfb-42a1-964d-87c1486adc32/steps) para comprender los conceptos de IAM.

## Instalación de la Maquina Virtual
Para el siguiente ejercicio se requiere una Maquina Virtual Flex de 1 OCPU y 8 Gb RAM con la imagen de Oracle Linux 8. Luego de su creación procedemos con la instalación de los siguientes pasos:

```sh
sudo dnf config-manager --set-enabled ol8_appstream
sudo dnf module list --all nodejs
sudo dnf module enable nodejs:18 -y
sudo dnf module install nodejs -y
sudo firewall-cmd --zone=public --add-port=3000/tcp --permanent
sudo firewall-cmd --reload
wget https://github.com/ociknowledge/ociz2h07/releases/download/v1.0.0/z2h.zip
```

En el archivo **auth.js**, se debe modificar las siguientes llaves:
- ClientId
- ClientSecret
- ClientTenant
- AudienceServiceUrl
- redirectURL
- mainURL

https://github.com/ociknowledge/ociz2h07/blob/dbf04361e2f7a551d1aa83fa7b97a929848d1f4e/auth.js#L3-L12

Luego de la edición del archivo **auth.js**, procedemos con los comandos finales.

```sh
rm -rf z2h
unzip z2h.zip -d z2h
cd z2h
npm i
mv passport-idcs node_modules/
nohup node app.js >> app.log 2>&1 &
```