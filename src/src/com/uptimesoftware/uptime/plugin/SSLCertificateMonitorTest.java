package com.uptimesoftware.uptime.plugin;

import static org.junit.Assert.*;

import java.security.cert.X509CRL;
import java.util.HashMap;

import org.junit.Test;

import com.uptimesoftware.uptime.plugin.SSLCertificateMonitor.UptimeSSLCertificateMonitor;

public class SSLCertificateMonitorTest {

	// Inputs from Up.time.
	private HashMap<String, Object> inputs = new HashMap<String, Object>();

	@Test
	public void test() {
		UptimeSSLCertificateMonitor testInstance = new UptimeSSLCertificateMonitor();

		String url = "http://crl.telecomputing.no/TeleComputing%20Norway%20Root%20Premium%20CA(1).crl";
		inputs.put(UptimeSSLCertificateMonitor.PATH_TO_CRL, url);
		X509CRL crl = testInstance.getX509CRLWithURL((String) inputs
				.get(UptimeSSLCertificateMonitor.PATH_TO_CRL));

		assertNotNull(crl);

		String filePath = "C:/Users/syoon/Desktop/TeleComputing Norway Root Premium CA.crl";
		inputs.put(UptimeSSLCertificateMonitor.PATH_TO_CRL, filePath);
		crl = testInstance.getX509CRLWithLocalFilePath((String) inputs
				.get(UptimeSSLCertificateMonitor.PATH_TO_CRL));

		assertNotNull(crl);

		int remainingDays = testInstance.calculateRemainingTime(crl);

		assertNotNull(remainingDays);
		System.out.println(remainingDays);
	}
}
