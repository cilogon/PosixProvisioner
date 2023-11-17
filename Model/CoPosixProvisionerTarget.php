<?php
/**
 * COmanage Registry LDAP User posixGroup target model
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
 * @package       registry-plugin
 * @since         COmanage Registry v2.0.0
 * @license       Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 */

App::uses("CoProvisionerPluginTarget", "Model");

class CoPosixProvisionerTarget extends CoProvisionerPluginTarget {
  // Define class name for cake
  public $name = "CoPosixProvisionerTarget";

  // Add behaviors
  public $actsAs = array('Containable');

  // Association rules from this model to other models
  public $belongsTo = array("CoProvisioningTarget");

  // Default display field for cake generated views
  public $displayField = "co_provisioning_target_id";

  // Validation rules for table elements
  public $validate = array(
    'co_provisioning_target_id' => array(
      'rule' => 'numeric',
      'required' => true,
      'message' => 'A CO Provisioning Target ID must be provided'
    )
  );

  /**
   * Provision for the specified CO Person.
   *
   * @since  COmanage Registry v2.0.0
   * @param  Array CO Provisioning Target data
   * @param  ProvisioningActionEnum Registry transaction type triggering provisioning
   * @param  Array Provisioning data, populated with ['CoPerson'] or ['CoGroup']
   * @return Boolean True on success
   * @throws RuntimeException
   */

  public function provision($coProvisioningTargetData, $op, $provisioningData) {
    CakeLog::write('error', "CoPosixProvisioner provision is called");
    CakeLog::write('error', "CoPosixProvisioner coProvisioningTargetData is " . print_r($coProvisioningTargetData, true));
    CakeLog::write('error', "CoPosixProvisioner op is " . print_r($op, true));
    CakeLog::write('error', "CoPosixProvisioner provisioningData is " . print_r($provisioningData, true));

    // We only provision CO Person objects and not CO Group objects.
    if (isset($provisioningData['CoGroup']['id'])) {
      return true;
    }

    $add = false;
    $delete = false;
    $modify = false;

    switch($op) {
      case ProvisioningActionEnum::CoPersonAdded:
      case ProvisioningActionEnum::CoPersonUnexpired:
      case ProvisioningActionEnum::CoPersonPetitionProvisioned:
      case ProvisioningActionEnum::CoPersonPipelineProvisioned:
      case ProvisioningActionEnum::CoPersonReprovisionRequested:
      case ProvisioningActionEnum::CoPersonUpdated:
        // We only provision CO Person records with status Active or GracePeriod.
        if(in_array($provisioningData['CoPerson']['status'],
                    array(StatusEnum::Active,
                          StatusEnum::GracePeriod))) {
          $add = true;
        }

        // Unlike the LDAP Provisioner, this provisioner does not record the DN written
        // to the LDAP directory in an SQL table so that if there are later changes
        // needed to the DN (for example if the Identifier changes and so the CN changes)
        // then the DN can be looked up and a modification/move invoked.
        //
        // Rather, it takes the approach of always doing a search/delete/add approach (for
        // add and modify). When the CO Person record is "deleted" then only a search/delete
        // is done. The search filter is based on the gidNumber, which is assumed to never
        // change.
        //
        // That is why delete is set to true here, and the test of delete below happens
        // before the test for add and modify.
        $delete = true;
        break;

      case ProvisioningActionEnum::CoPersonExpired:
      case ProvisioningActionEnum::CoPersonDeleted:
        $delete = true;
        break;
      case ProvisioningActionEnum::CoPersonEnteredGracePeriod:
        // no change to user group at this point
        break;
      default:
        $msg = "CoPosixProvisioner Provisioning action not handled";
        CakeLog::write('error', $msg);
        throw new RuntimeException($msg);
        break;
    }

    $CoLdapProvisionerTarget = ClassRegistry::init('LdapProvisioner.CoLdapProvisionerTarget');

    $args = array();
    $args['conditions']['CoLdapProvisionerTarget.id'] = $coProvisioningTargetData['CoPosixProvisionerTarget']['co_ldap_provisioner_target_id'];
    $args['contain'] = false;

    $ldapTarget = $CoLdapProvisionerTarget->find('first', $args);

    if(empty($ldapTarget)) {
      $msg = "CoPosixProvisioner No valid LDAP provisioner specified";
      CakeLog::write('error', $msg);
      throw new RuntimeException($msg);
    }

    $groupBaseDn = $ldapTarget['CoLdapProvisionerTarget']['group_basedn'];

    // Inspect the Identifiers for the CO Person record and for the
    // configured Identifier type construct the DN. Also record
    // the gidNumber and uidNumber to be used for the summary
    // posixGroup.
    foreach($provisioningData['Identifier'] as $identifier) {
      if(!empty($identifier['type'])
         && !empty($identifier['identifier'])
         && $identifier['status'] == StatusEnum::Active) {

            if ($identifier['type'] == $ldapTarget['CoLdapProvisionerTarget']['dn_identifier_type']) {
                $cn = $identifier['identifier'];
                $dn = "cn=" . $cn . "," . $groupBaseDn;
            }

            if ($identifier['type'] == 'gidNumber') {
                 $gidNumber = $identifier['identifier'];
            }

            if ($identifier['type'] == 'uid') {
                 $uidNumber = $identifier['identifier'];
            }
      }
    }

    if(empty($gidNumber)) {
      $msg = "CoPosixProvisioner gidNumber not set";
      CakeLog::write('error', $msg);
      throw new UnderflowException($msg);
    }

    if (empty($dn)) {
      $msg = "CoPosixProvisioner DN not set";
      CakeLog::write('error', $msg);
      throw new UnderflowException($msg);
    }

    if(empty($uidNumber)) {
      $msg = "CoPosixProvisioner uid not set";
      CakeLog::write('error', $msg);
      throw new UnderflowException($msg);
    }

    CakeLog::write('error', "CoPosixProvisoner posixGroup DN is " . $dn);

    // Construct the attributes for the posixGroup record.
    $attributes = array();
    $attributes['objectClass'] = ['posixGroup'];
    $attributes['cn'] = $cn;
    $attributes['gidNumber'] = $gidNumber;

    CakeLog::write('error', "CoPosixProvisioner posixGroup attributes are " . print_r($attributes, true));

    // Bind to the server.
    $cxn = ldap_connect($ldapTarget['CoLdapProvisionerTarget']['serverurl']);

    if(!$cxn) {
      $msg =_txt('er.ldapprovisioner.connect');
      CakeLog::write('error', $msg);
      throw new RuntimeException($msg, 0x5b /*LDAP_CONNECT_ERROR*/);
    }

    ldap_set_option($cxn, LDAP_OPT_PROTOCOL_VERSION, 3);

    if(!@ldap_bind($cxn,
                   $ldapTarget['CoLdapProvisionerTarget']['binddn'],
                   $ldapTarget['CoLdapProvisionerTarget']['password'])) {
      CakeLog::write('error', ldap_error($cxn));
      CakeLog::write('error', ldap_errno($cxn));
      throw new RuntimeException(ldap_error($cxn), ldap_errno($cxn));
    }

    // Only modify the directory with the individual CO Person record posixGroup 
    // when the summary group has cn=IGWN (exclude cn=cwarchive and all others).
    if($coProvisioningTargetData['CoPosixProvisionerTarget']['cn'] == 'IGWN') {
      // The test for delete must remain first. See comments above for
      // why.

      if ($delete) {
        // Search to find the record, but in order to more easily handle
        // DN changes (because the CN changed because the Identifier value
        // changed), search using the gidNumber, which should not change.
        $filter = "(&(gidNumber=$gidNumber)(objectClass=posixGroup))";
        CakeLog::write('error', "CoPosixProvisioner Searching using filter " . $filter);

        $searchResult = ldap_search($cxn, $groupBaseDn, $filter, array('dn'));

        // If we found a record then delete it.
        if($searchResult) {
          $entries = ldap_get_entries($cxn, $searchResult);
          $entryCount = $entries["count"];
          CakeLog::write('error', "CoPosixProvisioner found $entryCount records");

          for ($i = 0; $i < $entryCount; $i++) {
            $rmdn = $entries[$i]["dn"];
            CakeLog::write('error', "CoPosixProvisioner About to delete DN " . $rmdn);
            ldap_delete($cxn, $rmdn);
            CakeLog::write('error', "CoPosixProvisioner Deleted DN " . $rmdn);
          }
        }
      }

      if ($add) {
        CakeLog::write('error', "CoPosixProvisioner About to add DN " . $dn);
        CakeLog::write('error', "CoPosixProvisioner attributes is " . print_r($attributes, true));
        if(!@ldap_add($cxn, $dn, $attributes)) {
          CakeLog::write('error', ldap_error($cxn));
          CakeLog::write('error', ldap_errno($cxn));
          throw new RuntimeException(ldap_error($cxn), ldap_errno($cxn));
        }

        CakeLog::write('error', "CoPosixProvisioner Added DN " . $dn);
      }

      if ($modify) {
        CakeLog::write('error', "CoPosixProvisioner About to replace DN " . $dn);
        CakeLog::write('error', "CoPosixProvisioner attributes is " . print_r($attributes, true));
        if(!@ldap_mod_replace($cxn, $dn, $attributes)) {
          CakeLog::write('error', ldap_error($cxn));
          CakeLog::write('error', ldap_errno($cxn));
          throw new RuntimeException(ldap_error($cxn), ldap_errno($cxn));
        }

        CakeLog::write('error', "CoPosixProvisioner Replaced DN " . $dn);
      }
    }

    // The work for the individual CO Person posixGroup is completed.

    // Next consider the single summary posixGroup.

    $summaryGroupCn = $coProvisioningTargetData['CoPosixProvisionerTarget']['cn'];
    $summaryGroupDn = "cn=" . $summaryGroupCn . "," . $groupBaseDn;
    $summaryGroupGid = $coProvisioningTargetData['CoPosixProvisionerTarget']['gid'];

    CakeLog::write('error', "CoPosixProvisioner Summary Group DN is $summaryGroupDn");

    // Check if summary group exists in the directory and if not create it.
    $filter = "(cn=" . $summaryGroupCn . ")";
    $searchResult = ldap_search($cxn, $groupBaseDn, $filter, array('dn','cn'));

    if($searchResult) {
      $entries = ldap_get_entries($cxn, $searchResult);
      $entryCount = $entries["count"];
      CakeLog::write('error', "CoPosixProvisioner found $entryCount records for the summary group with DN $summaryGroupDn");

      if($entryCount < 1) {
        CakeLog::write('error', "CoPosixProvisioner creating record with DN $summaryGroupDn");
        $attributes = array();
        $attributes['objectClass'] = ['posixGroup'];
        $attributes['gidNumber'] = $summaryGroupGid;

        CakeLog::write('error', "CoPosixProvisioner summary group attributes are " . print_r($attributes, true));

        if(!ldap_add($cxn, $summaryGroupDn, $attributes)) {
          CakeLog::write('error', ldap_error($cxn));
          CakeLog::write('error', ldap_errno($cxn));
          throw new RuntimeException(ldap_error($cxn), ldap_errno($cxn));
        }

        CakeLog::write('error', "CoPosixProvisioner created record with DN $summaryGroupDn");
      } else {
        CakeLog::write('error', "CoPosixProvisioner Summary Group with DN $summaryGroupDn exists in directory");
      }
    }

    $attributes = array();
    $attributes['memberUid'] = $uidNumber;

    if($delete && !$add) {
      // Remove the user from the summary group.
      CakeLog::write('error', "CoPosixProvisioner removing attribute memberUid = $uidNumber from summary group DN $summaryGroupDn");

      // Eat the delete error. Modify use case seems to call delete than error, and the value may not exist legitimately.
      // And if we want to just scrug the records and add from scratch, eating error makes sense.
      ldap_mod_del($cxn, $summaryGroupDn, $attributes);
    }

    if($add) {
      // Add the user to the summary group.
      CakeLog::write('error', "CoPosixProvisioner adding attribute memberUid = $uidNumber to summary group DN $summaryGroupDn");

      ldap_mod_add($cxn, $summaryGroupDn, $attributes);
    }

    // Unbind the connection.
    ldap_unbind($cxn);

    // Return true to signal the provisioning succeeded.
    return true;
  }
}
