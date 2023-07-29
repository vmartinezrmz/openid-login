<?php
/*
Plugin Name: OpenID Login
Plugin URI: https://vickmtz.mx/plugins/openid-login
Description: Plugin para agregar inicio de sesión con OpenID a YOURLS.
Version: 1.0
Author: VickMtz
Author URI: https://vickmtz.mx
*/

// No direct call
if (!defined('YOURLS_ABSPATH')) die();

require __DIR__ . '/vendor/autoload.php';

use League\OAuth2\Client\Provider\GenericProvider;

function get_openid_login_url(String $route = '/openid-login')
{
    $siteUrl = yourls_site_url(false);
    $url = rtrim($siteUrl, '/') . '/' . $route;
    return $url;
}

// Agrega el botón de inicio de sesión con OpenID en la página de inicio de sesión
yourls_add_action('login_form_bottom', 'openid_login_button');

function openid_login_button()
{
    echo '<div style="text-align:center;"><a href="' . get_openid_login_url('openid-login') . '" class="button">' . OIDC_LABEL_BUTTON . '</a></div>';
}

// Ruta para la autenticación de OpenID
yourls_add_action('plugins_loaded', 'openid_login_handle_authentication');

function openid_login_handle_authentication()
{
    $requestUri = $_SERVER['REQUEST_URI'];

    // Verificar si la solicitud es para la ruta de autenticación de OpenID
    if (!yourls_is_API() && strpos($requestUri, 'openid-login') !== false) {


        $provider = ProviderInstance();
        // Generar la URL de autorización
        $authorizationUrl = $provider->getAuthorizationUrl();

        // Redirigir al usuario para la autorización
        yourls_redirect($authorizationUrl, 303);
        exit();
    }
}

// Manejar el callback de OpenID
yourls_add_action('redirect_keyword_not_found', 'openid_page_hook');

function openid_page_hook($args)
{
    $keyword = $args[0];

    if ($keyword === 'openid-callback') {
        $code = isset($_GET['code']) ? $_GET['code'] : '';

        if (empty($code)) {
            yourls_redirect(yourls_admin_url('index.php'), 303);
            exit();
        }

        try {

            $provider = ProviderInstance();
            // Intercambiar el código de autorización por un token de acceso
            $accessToken = $provider->getAccessToken('authorization_code', [
                'code' => $code
            ]);

            // Obtener los detalles del usuario autenticado
            $resourceOwner = $provider->getResourceOwner($accessToken)->toArray();

            session_start();
            $_SESSION['access_token'] = $accessToken;
            $_SESSION['username'] = $resourceOwner['preferred_username'];
            $_SESSION['sub'] = $resourceOwner['sub'];
            $_SESSION['email'] = $resourceOwner['email'];

            yourls_redirect(yourls_admin_url());
            exit();
        } catch (\Exception $e) {
            // Manejar el error de autenticación
            yourls_redirect(yourls_admin_url('?error=' . $e->getMessage()));
            exit();
        }
    }
}

// Validar al usuario autenticado
yourls_add_filter('is_valid_user', 'openid_is_valid_user');

function openid_is_valid_user($value)
{
    // Iniciar sesión si no está iniciada
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (isset($_SESSION['email'])) {
        yourls_set_user($_SESSION['email']);
        return true;
    }

    return $value;
}

// Manejar el cierre de sesión
yourls_add_action('logout', 'openid_logout_hook');

function openid_logout_hook()
{
    // Iniciar sesión si no está iniciada
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    yourls_store_cookie(null);

    // Eliminar la información de la sesión
    unset($_SESSION['username']);
    unset($_SESSION['email']);
    unset($_SESSION['sub']);
    unset($_SESSION['access_token']);

    // Redirigir al usuario a la página de inicio de sesión
    yourls_redirect(yourls_admin_url('index.php'));
    exit();
}

// Agrega un enlace al menú de administrador
yourls_add_filter('admin_menu', 'add_custom_menu_item');

function add_custom_menu_item()
{
    // Iniciar sesión si no está iniciada
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (isset($_SESSION['email'])) {
        echo '<li><a href="' . OIDC_BASE_URL . '/account" target="_blank">Perfil</a></li>';
    }
}

yourls_add_action('html_logo', 'add_custom_disclaimer');

function add_custom_disclaimer()
{
    // Iniciar sesión si no está iniciada
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    if (isset($_SESSION['email'])) {
        echo "<strong>Este cuenta se rigue por un servidor de autorizaci&oacute;n por favor si tiene dudas contacte a su administrador.</strong>";
    }
}

function ProviderInstance()
{
    // Crear una instancia del proveedor OAuth2
    $provider = new GenericProvider([
        'clientId' => OIDC_CLIENT_NAME,
        'clientSecret' => OIDC_CLIENT_SECRET,
        'redirectUri' => get_openid_login_url('openid-callback'),
        'urlAuthorize' => OIDC_BASE_URL . '/auth',
        'urlAccessToken' => OIDC_BASE_URL . '/token',
        'urlResourceOwnerDetails' => OIDC_BASE_URL . '/userinfo'
    ]);

    return $provider;
}
