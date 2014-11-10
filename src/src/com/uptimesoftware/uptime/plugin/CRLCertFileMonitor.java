package com.uptimesoftware.uptime.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.HashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ro.fortsoft.pf4j.PluginWrapper;
import com.uptimesoftware.uptime.plugin.api.Extension;
import com.uptimesoftware.uptime.plugin.api.Plugin;
import com.uptimesoftware.uptime.plugin.api.PluginMonitor;
import com.uptimesoftware.uptime.plugin.monitor.MonitorState;
import com.uptimesoftware.uptime.plugin.monitor.Parameters;

/**
 * CRL Cert File Monitor
 * 
 * @author uptime software
 */
public class CRLCertFileMonitor extends Plugin {

	/**
	 * Constructor - a plugin wrapper.
	 * 
	 * @param wrapper
	 */
	public CRLCertFileMonitor(PluginWrapper wrapper) {
		super(wrapper);
	}

	/**
	 * A nested static class which has to extend PluginMonitor.
	 * 
	 * Functions that require implementation :
	 * 1) The monitor function will implement the main functionality and should set the monitor's
	 * state and result message prior to completion.
	 * 2) The setParameters function will accept a Parameters object containing the values filled
	 * into the monitor's configuration page in Up.time.
	 */
	@Extension
	public static class UptimeCRLCertFileMonitor extends PluginMonitor {
		// Logger object.
		private static final Logger logger = LoggerFactory
				.getLogger(UptimeCRLCertFileMonitor.class);

		// Inputs from Up.time.
		private HashMap<String, Object> inputs = new HashMap<String, Object>();

		// Non-input constants
		static final int ONE_SECOND_IN_MILLISECONDS = 1000;
		static final int ONE_MINUTE_IN_SECONDS = 60;
		static final int ONE_HOUR_IN_MINUTES = 60;
		static final int ONE_DAY_IN_HOURS = 24;
		static final String X_509 = "X.509";

		// Monitor message.
		String monitorMessage = "";

		// Input constants.
		static final String HOSTNAME = "hostname";
		static final String PATH_TO_CRL = "pathToCRL";

		// Output constants.
		static final String CERT_VERSION = "certVersion";
		static final String CERT_TYPE = "certType";
		static final String SIG_ALG_NAME = "sigAlgName";
		static final String ISSUER_NAME = "issuerName";
		static final String THIS_UPDATE = "thisUpdate";
		static final String NEXT_UPDATE = "nextUpdate";
		static final String EXPIRY_DAYS = "expiryDays";

		/**
		 * The setParameters function will accept a Parameters object containing the values filled
		 * into the monitor's configuration page in Up.time.
		 * 
		 * @param params
		 *            Parameters object which contains inputs.
		 */
		@Override
		public void setParameters(Parameters params) {
			logger.debug("Step 1 : Setting parameters.");
			// See definition in .xml file for plugin. Each plugin has different number of
			// input/output parameters.
			inputs.put(HOSTNAME, params.getString(HOSTNAME));
			inputs.put(PATH_TO_CRL, params.getString(PATH_TO_CRL));
		}

		/**
		 * The monitor function will implement the main functionality and should set the monitor's
		 * state and result message prior to completion.
		 */
		@Override
		public void monitor() {
			logger.debug("Get X509CRL instance with a given CRL file URL.");
			X509CRL crl = getX509CRLWithURL((String) inputs.get(PATH_TO_CRL));

			if (crl == null) {
				logger.debug("Try with local file path again.");
				crl = getX509CRLWithLocalFilePath((String) inputs.get(PATH_TO_CRL));
			}

			if (crl == null) {
				logger.debug("Failed to get X509CRL instance with a given path string.");
				setStateAndMessage(MonitorState.UNKNOWN, monitorMessage);
				return;
			}

			addVariable(CERT_VERSION, crl.getVersion());
			addVariable(CERT_TYPE, crl.getType());
			addVariable(SIG_ALG_NAME, crl.getSigAlgName());
			addVariable(ISSUER_NAME, crl.getIssuerX500Principal().getName());
			addVariable(THIS_UPDATE, crl.getThisUpdate().toString());
			addVariable(NEXT_UPDATE, crl.getNextUpdate().toString());
			addVariable(EXPIRY_DAYS, calculateRemainingTime(crl));

			setStateAndMessage(MonitorState.OK, "Monitor ran successfully.");
		}

		/**
		 * Get X509CRL instance with a given URL string.
		 * 
		 * @param pathToCRL
		 *            URL string input from Up.Time.
		 * @return X509CRL instance.
		 */
		X509CRL getX509CRLWithURL(String pathToCRL) {
			X509CRL crl = null;
			CertificateFactory cf = null;
			try {
				cf = CertificateFactory.getInstance(X_509);
				URL url = new URL(pathToCRL);
				crl = (X509CRL) cf.generateCRL(url.openStream());
			} catch (CertificateException e) {
				monitorMessage = "Failed to create CertificateFactory X.509 instance.";
				logger.error(monitorMessage, e);
				return crl;
			} catch (MalformedURLException e) {
				logger.warn("Input pathToCRL is not URL. Try with file path.", e);
				return crl;
			} catch (CRLException e) {
				monitorMessage = "Failed to create X509CRL instance with a given URL.";
				logger.error(monitorMessage, e);
				return crl;
			} catch (IOException e) {
				monitorMessage = "Failed to open input stream with a given URL.";
				logger.error(monitorMessage, e);
				return crl;
			}
			return crl;
		}

		/**
		 * Get X509CRL instance with a given local file path string.
		 * 
		 * @param pathToCRL
		 *            Local file path string input from Up.Time.
		 * @return X509CRL instance.
		 */
		X509CRL getX509CRLWithLocalFilePath(String pathToCRL) {
			X509CRL crl = null;
			CertificateFactory cf = null;
			File file = Paths.get(pathToCRL).toFile();
			try {
				cf = CertificateFactory.getInstance(X_509);
				crl = (X509CRL) cf.generateCRL(new FileInputStream(file));
			} catch (CertificateException e) {
				monitorMessage = "Failed to create CertificateFactory X.509 instance.";
				logger.error(monitorMessage, e);
				return crl;
			} catch (CRLException e) {
				monitorMessage = "Failed to create X509CRL instance with a given local file path.";
				logger.error(monitorMessage, e);
				return crl;
			} catch (FileNotFoundException e) {
				monitorMessage = "Failed to find a file with a given local file path.";
				logger.error(monitorMessage, e);
				return crl;
			}
			return crl;
		}

		/**
		 * Calculate remaining time until certificate expiration date.
		 * 
		 * @param crl
		 *            X509CRL object from a given file path to CRL.
		 * @return Remaining days until certificate expiration.
		 */
		int calculateRemainingTime(X509CRL crl) {
			// nextUpdate - currentTime.
			long diff = crl.getNextUpdate().getTime() - (new Date()).getTime();
			int diffDays = (int) (diff / (ONE_DAY_IN_HOURS * ONE_HOUR_IN_MINUTES
					* ONE_MINUTE_IN_SECONDS * ONE_SECOND_IN_MILLISECONDS));

			return diffDays;
		}
	}
}