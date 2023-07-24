<?php

namespace Drupal\auth0\Util;

/**
 * @file
 * Contains \Drupal\auth0\Util\AuthHelper.
 */

use Auth0\SDK\Utility\HttpTelemetry;

use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Controller routines for auth0 authentication.
 */
class AuthHelper {
  const AUTH0_DOMAIN = 'auth0_domain';
  const AUTH0_CUSTOM_DOMAIN = 'auth0_custom_domain';

  /**
   * The module configuration.
   *
   * @var \Drupal\Core\Config\ImmutableConfig
   */
  private $config;

  /**
   * Auth0 domain.
   *
   * @var array|mixed|null
   */
  private $domain;

  /**
   * Auth0 custom domain.
   *
   * @var array|mixed|null
   */
  private $customDomain;

  /**
   * Database.
   *
   * @var \Drupal\Core\Database\Connection
   */
  protected Connection $database;

  /**
   * Initialize the Helper.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   */
  public function __construct(ConfigFactoryInterface $config_factory) {
    $this->config = $config_factory->get('auth0.settings');
    $this->domain = $this->config->get(AuthHelper::AUTH0_DOMAIN);
    $this->customDomain = $this->config->get(AuthHelper::AUTH0_CUSTOM_DOMAIN);
    $this->database = \Drupal::database();

    self::setTelemetry();
  }

  /**
   * Extend Auth0 PHP SDK telemetry to report for Drupal.
   */
  public static function setTelemetry() {
    HttpTelemetry::setPackage('auth0-drupal', AUTH0_MODULE_VERSION);
  }

  /**
   * Return the custom domain, if one has been set.
   *
   * @return mixed
   *   A string with the domain name
   *   A empty string if the config is not set
   */
  public function getAuthDomain() {
    return !empty($this->customDomain) ? $this->customDomain : $this->domain;
  }

  /**
   * Get the tenant CDN base URL based on the Application domain.
   *
   * @param string $domain
   *   Tenant domain.
   *
   * @return string
   *   Tenant CDN base URL
   */
  public static function getTenantCdn($domain) {
    preg_match('/^[\w\d\-_0-9]+\.([\w\d\-_0-9]*)[\.]*auth0\.com$/', $domain, $matches);
    return 'https://cdn' .
      (empty($matches[1]) || $matches[1] == 'us' ? '' : '.' . $matches[1])
      . '.auth0.com';
  }

  /**
   * Get the auth0 user profile.
   */
  public function findAuth0User($id) {
    $auth0_user = $this->database->select('auth0_user', 'a')
      ->fields('a', ['drupal_id'])
      ->condition('auth0_id', $id, '=')
      ->execute()
      ->fetchAssoc();

    return empty($auth0_user) ? FALSE : $this->entityTypeManager()->getStorage('user')->load($auth0_user['drupal_id']);
  }


}
