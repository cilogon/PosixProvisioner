<?php
/**
 * COmanage Registry CO Homedir Provisioner Targets Controller
 *
 * Portions licensed to the University Corporation for Advanced Internet
 * Development, Inc. ("UCAID") under one or more contributor license agreements.
 * See the NOTICE file distributed with this work for additional information
 * regarding copyright ownership.
 *
 * UCAID licenses this file to you under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @link          http://www.internet2.edu/comanage COmanage Project
 * @package       registry
 * @since         COmanage Registry v0.9
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */
App::uses("SPTController", "Controller");

class CoPosixProvisionerTargetsController extends SPTController {
  // Class name, used by Cake
  public $name = "CoPosixProvisionerTargets";

  // Establish pagination parameters for HTML views
  public $paginate = array(
    'limit' => 25,
    'order' => array(
      'co_ldap_provisioner_target_id' => 'asc'
    )
  );

  public $uses = array(
    'PosixProvisioner.CoPosixProvisionerTarget',
    'CoProvisioningTarget'
    //'CoService'
  );


  /**
   * Callback after controller methods are invoked but before views are rendered.
   *
   * @since  COmanage Registry v2.0.0
   */

  function beforeRender() {
    parent::beforeRender();

    // Pull the available LDAP Provisioners and CO Services (with tokens enabled)

    $this->CoProvisioningTarget->bindModel(array('hasOne' =>
                                                 array('LdapProvisioner.CoLdapProvisionerTarget')),
                                           false);

    $args = array();
    $args['conditions']['CoProvisioningTarget.co_id'] = $this->cur_co['Co']['id'];
    $args['conditions']['CoProvisioningTarget.plugin'] = 'LdapProvisioner';
    $args['contain'][] = 'CoLdapProvisionerTarget';

    $ldapProvisioners = $this->CoProvisioningTarget->find('all', $args);

    $availableTargets = array();

    foreach($ldapProvisioners as $lp) {
      $availableTargets[ $lp['CoLdapProvisionerTarget']['id'] ] = $lp['CoProvisioningTarget']['description'];
    }

    $this->set('vv_ldap_provisioners', $availableTargets);

    /*
    $this->CoService->bindModel(array('hasOne' =>
                                      array('CoServiceToken.CoServiceTokenSetting')),
                                false);

    $args = array();
    $args['conditions']['CoService.co_id'] = $this->cur_co['Co']['id'];
    $args['contain'][] = 'CoServiceTokenSetting';

    $services = $this->CoService->find('all', $args);

    $enabledServices = array();

    // We only want enabled services.

    foreach($services as $svc) {
      if(isset($svc['CoServiceTokenSetting']['enabled']) && $svc['CoServiceTokenSetting']['enabled']) {
        $enabledServices[ $svc['CoServiceTokenSetting']['co_service_id'] ] = $svc['CoService']['name'];
      }
    }

    $this->set('vv_enabled_services', $enabledServices);
    */
  }

  /**
   * Authorization for this Controller, called by Auth component
   * - precondition: Session.Auth holds data used for authz decisions
   * - postcondition: $permissions set with calculated permissions
   *
   * @since  COmanage Registry v0.9
   * @return Array Permissions
   */

  function isAuthorized() {
    $roles = $this->Role->calculateCMRoles();

    // Construct the permission set for this user, which will also be passed to the view.
    $p = array();

    // Determine what operations this user can perform

    // Delete an existing CO Provisioning Target?
    $p['delete'] = ($roles['cmadmin'] || $roles['coadmin']);

    // Edit an existing CO Provisioning Target?
    $p['edit'] = ($roles['cmadmin'] || $roles['coadmin']);

    // View all existing CO Provisioning Targets?
    $p['index'] = ($roles['cmadmin'] || $roles['coadmin']);

    // View an existing CO Provisioning Target?
    $p['view'] = ($roles['cmadmin'] || $roles['coadmin']);

    $this->set('permissions', $p);
    return($p[$this->action]);
  }
}
