<?php

namespace Drupal\auth0;

use Drupal\Core\Security\TrustedCallbackInterface;

/**
 * Provides a trusted callback for the User Login block.
 *
 */
class Auth0BlockUserLoginViewBuilder implements TrustedCallbackInterface {

  /**
   * {@inheritdoc}
   */
  public static function trustedCallBacks() {
    return ['preRender'];
  }

  /**
   * Pre-render callback for block user_login_block.
   */
  public static function preRender(array $build) {
    var_dump(array_keys($build['content']));
    var_dump(array_keys($build));
    unset($build['content']['user_links']['request_password']);
    return $build;
  }

}
