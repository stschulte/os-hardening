#include <stdlib.h>
#include <stdio.h>
#include <mntent.h>
#include <string.h>

#include <rpm/header.h>
#include <rpm/rpmlib.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmts.h>

#include <harden/check.h>
#include <harden/report.h>
#include <harden/collector/rpm.h>

int package_installed(const char* name) {
  int found = 0;

  /* create RPM transaction */
  rpmts ts = rpmtsCreate();

  /* create an iterator that searches for a name */
  rpmdbMatchIterator mi = rpmtsInitIterator(ts, RPMTAG_NAME, name, 0);

  Header h;

  while((h = rpmdbNextIterator(mi)) != NULL) {
    found = 1;
    break;
  }

  rpmdbFreeIterator(mi);
  rpmtsFree(ts);
    
  return found;
}

int collector_rpm_evaluate(struct report* report) {
  struct check* setroubleshoot = check_new("cis", "1.4.4", "Remove SETroubleshoot", CHECK_PASSED);
  struct check* mcstranslation = check_new("cis", "1.4.5", "Remove MCS Translation Service (mcstrans)", CHECK_PASSED);
  struct check* telnetserver   = check_new("cis", "2.1.1", "Remove telnet-server", CHECK_PASSED);
  struct check* telnetclient   = check_new("cis", "2.1.2", "Remove telnet Clients", CHECK_PASSED);
  struct check* rshserver      = check_new("cis", "2.1.3", "Remove rsh-server", CHECK_PASSED);
  struct check* rshclient      = check_new("cis", "2.1.4", "Remove rsh", CHECK_PASSED);
  struct check* nisclient      = check_new("cis", "2.1.5", "Remove NIS Client", CHECK_PASSED);
  struct check* nisserver      = check_new("cis", "2.1.6", "Remove NIS Server", CHECK_PASSED);
  struct check* tftpclient     = check_new("cis", "2.1.7", "Remove tftp", CHECK_PASSED);
  struct check* tftpserver     = check_new("cis", "2.1.8", "Remove tftp-server", CHECK_PASSED);
  struct check* talkclient     = check_new("cis", "2.1.9", "Remove talk", CHECK_PASSED);
  struct check* talkserver     = check_new("cis", "2.1.10", "Remove talk-server", CHECK_PASSED);
  struct check* xinetd         = check_new("cis", "2.1.11", "Remove xinetd", CHECK_PASSED);

  rpmReadConfigFiles(NULL, NULL);

  if(package_installed("setroubleshoot") == 1) {
    check_add_finding(setroubleshoot, "rpm package setroubleshoot is installed but should be absent"); 
  }

  if(package_installed("mcstrans") == 1) {
    check_add_finding(mcstranslation, "rpm package mcstrans is installed but should be absent"); 
  }

  if(package_installed("telnet-server") == 1) {
    check_add_finding(telnetserver, "rpm package telnet-server is installed but should be absent"); 
  }

  if(package_installed("telnet") == 1) {
    check_add_finding(telnetclient, "rpm package telnet is installed but should be absent"); 
  }

  if(package_installed("rsh-server") == 1) {
    check_add_finding(rshserver, "rpm package rsh-server is installed but should be absent");
  }

  if(package_installed("rsh") == 1) {
    check_add_finding(rshclient, "rpm package rsh is installed but should be absent");
  }

  if(package_installed("ypbind") == 1) {
    check_add_finding(nisclient, "rpm package ypbind is installed but should be absent");
  }

  if(package_installed("ypserv") == 1) {
    check_add_finding(nisserver, "rpm package ypserv is installed but should be absent");
  }

  if(package_installed("tftp") == 1) {
    check_add_finding(tftpclient, "rpm package ypserv is installed but should be absent");
  }

  if(package_installed("tftp-server") == 1) {
    check_add_finding(tftpserver, "rpm package tftp-server is installed but should be absent");
  }

  if(package_installed("talk") == 1) {
    check_add_finding(talkclient, "rpm package talk is installed but should be absent");
  }

  if(package_installed("talk-server") == 1) {
    check_add_finding(talkserver, "rpm package talk-server is installed but should be absent");
  }

  if(package_installed("xinetd") == 1) {
    check_add_finding(xinetd, "rpm package xinetd is installed but should be absent");
  }

  rpmFreeRpmrc();

  report_add_check(report, setroubleshoot);
  report_add_check(report, mcstranslation);
  report_add_check(report, telnetserver);
  report_add_check(report, telnetclient);
  report_add_check(report, rshserver);
  report_add_check(report, rshclient);
  report_add_check(report, nisclient);
  report_add_check(report, nisserver);
  report_add_check(report, tftpclient);
  report_add_check(report, tftpserver);
  report_add_check(report, talkclient);
  report_add_check(report, talkserver);
  report_add_check(report, xinetd);
  return 0;
}
