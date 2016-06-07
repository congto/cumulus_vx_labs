## Automated Lab Deployments Using Ansible

#### Notes on the Automation:
Vagrant creates a NAT network with eth0 of all Cumulus VX and Ubuntu boxes, forwarding a localhost TCP port to port 22 of the guest for SSH access. This is how the wrapper ```vagrant ssh <vm>``` works.

While this works well for purely local SSH access, it inherently makes it hard to connect and develop with these devices as if they were actual remote network nodes. If you do want the ```ssh vagrant@vm``` style access expected of real hosts, consider using the Vagrant-to-Local script available at the following link. This is **not** required for this demo.

* https://github.com/slaffer-au/vagrant-to-local

#### Setting Up for Automation
1. Change to the ansible directory
2. Ensure all hosts are accessible by Ansible with the ad-hoc command ```ansible all -m ping -u vagrant```.

---

## Pre-built Labs
* #### 1 Spine - 2 Leaf - 2 Host
  * **_VLAN Aware Bridging_**
    * VLAN aware bridging is configured on Spine and Leaf switches, enabling connectivity between Host1 and Host2
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=1spine_2leaf_2host lab=vlan_aware_bridge"`
  * **_OSPF Unnumbered_**
    * OSPF unnumbered is configured on Spine and Leaf switches, enabling connectivity between Host1 and Host2
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=1spine_2leaf_2host lab=ospf_unnumbered"`
  * **_BGP Unnumbered_**
    * BGP unnumbered is configured on Spine and Leaf switches, enabling connectivity between Host1 and Host2
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=1spine_2leaf_2host lab=bgp_unnumbered"`

* #### 2 Spine - 2 Leaf - 2 Host
  * **_Redistribute Neighbor_**
    * Leaf swtiches are confgiured for redistribute neighbor, one host per leaf, with a single uplink
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=2spine_2leaf_2host lab=rdnbrd"`

* #### 2 Spine - 4 Leaf - 2 Host
  * **_VXLAN with CLAG_**
    * Leaf switches are configured with CLAG down to the hosts, and VXLAN between leaf pods.
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=2spine_4leaf_2host lab=vxlan_with_clag"`
  * **_Redistribute Neighbor_**
    * Leaf switches are configured for redistribute neighbor, for uplink redundancy without configuring CLAG.
      * Deployment: `ansible-playbook conf-restore.yml --extra-vars "topology=2spine_4leaf_2host lab=rdnbrd"`

## Saving a Custom Lab
If you create a new lab from the base topology or would just like to save changes you have made to an existing lab, this can be done using the conf-backup.yml playbook. To save a lab:
  * `ansible-playbook conf-backup.yml --extra-vars "topology=<topology-name> lab=<lab-name>"`

This will copy the configuration files of each host specified in the conf_files variable defined under each role to the topology/\<topology-name\>/\<lab-name\>/\<hostname\> directory. This command will need to be run after any changes are made, which are desired to be saved.

To later restore these configurations:
  * `ansible-playbook conf-restore.yml --extra-vars "topology=<topology-name> lab=<lab-name>"`
