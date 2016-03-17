## Automated Lab Deployments Using Ansible

#### Notes on the Automation:
Vagrant creates a NAT network with eth0 of all Cumulus VX and Ubuntu boxes, forwarding a localhost TCP port to port 22 of the guest for SSH access. This is how the wrapper ```vagrant ssh <vm>``` works.

While this works well for purely local SSH access, it inherently makes it hard to connect and develop with these devices as if they were actual remote network nodes. If you do want the ```ssh vagrant@vm``` style access expected of real hosts, consider using the Vagrant-to-Local script available at the following link. This is **not** required for this demo.

* https://github.com/slaffer-au/vagrant-to-local

#### Setting Up for Automation
1. Change to the ansible directory
2. Ensure all hosts are accessible by Ansible with the ad-hoc command ```ansible all -m ping -u vagrant```.

---

## Labs
* ### 1 Spine - 2 Leaf - 2 Host

* ### 2 Spine - 2 Leaf - 2 Host

* ### 2 Spine - 4 Leaf - 2 Host
 * #### VXLAN with CLAG
 Leaf switches are configured with CLAG down to the hosts, and VXLAN between leaf pods.
