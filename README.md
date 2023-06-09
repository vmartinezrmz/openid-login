OpenID Login Plugin
===================

Plugin para agregar inicio de sesión con OpenID a YOURLS.

Requisitos
----------

- YOURLS 1.7.10 o superior.
- PHP 7.0 o superior.
- La extensión cURL de PHP habilitada.

Instalación
-----------

1. Clona o descarga este repositorio.
2. Copia el directorio `openid-login` en la carpeta `user/plugins` de tu instalación de YOURLS.
3. Ejecuta `composer install` dentro de la carpeta `openid-login` para instalar las dependencias.
4. Asegúrate de que la carpeta `openid-login/vendor` tenga permisos de escritura.
5. Renombra el archivo `config-sample.php` a `config.php`.
6. En el archivo `config.php`, define las siguientes constantes con los valores correspondientes de tu proveedor OpenID:

``
    define('OIDC_BASE_URL', 'URL_de_tu_proveedor_OpenID');
    define('OIDC_CLIENT_NAME', 'tu_client_id');
    define('OIDC_CLIENT_SECRET', 'tu_client_secret');
    define('OIDC_LABEL_BUTTON', 'Texto_del_boton_de_inicio_de_sesion');
``

7. Accede a la página de administración de YOURLS.
8. Activa el plugin 'OpenID Login' en la sección de 'Manage Plugins'.
9. ¡Listo! Ahora podrás ver el botón de inicio de sesión con OpenID en la página de inicio de sesión de YOURLS.

Configuración adicional
-----------------------

- Puedes personalizar el texto del botón de inicio de sesión modificando el valor de la constante `OIDC_LABEL_BUTTON` en el archivo `config.php`.
- Si deseas cambiar la apariencia del botón, puedes agregar estilos CSS personalizados en tu tema YOURLS.

Contribuciones
--------------

Si encuentras algún problema o tienes alguna sugerencia de mejora, por favor, abre un problema en el repositorio de GitHub.

Licencia
--------

Este plugin se distribuye bajo la Licencia MIT.
