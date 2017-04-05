import logging
import requests
import re
from bs4 import BeautifulSoup
from minemeld.ft.basepoller import BasePollerFT

LOG = logging.getLogger(__name__)


class Miner(BasePollerFT):
    def configure(self):
        super(Miner, self).configure()

        self.polling_timeout = self.config.get('polling_timeout', 20)
        self.verify_cert = self.config.get('verify_cert', True)

        self.output_type = self.config.get('output_type')
        if self.output_type.lower() not in ['file.name', 'email-addr', 'IPv4', 'URL']:
            raise ValueError('%s - Output type must be one of domain, ip, url, md5' % self.name)

        self.url = 'http://blog.dynamoo.com/'


    def _build_iterator(self, item):
        # builds the request and retrieves the page
        rkwargs = dict(
            stream=False,
            verify=self.verify_cert,
            timeout=self.polling_timeout
        )

        r = requests.get(
            self.url,
            **rkwargs
        )

        try:
            r.raise_for_status()
        except:
            LOG.debug('%s - exception in request: %s %s',
                      self.name, r.status_code, r.content)
            raise

        # Get links to other pages
        try:
            # Get Article Links
            soup = BeautifulSoup(r.content)
            find_links = soup.findAll("h3")
            list_links = re.findall('http://blog.dynamoo.com/.*?.html', str(find_links))
            LOG.debug("Found {0} Internal links".format(len(list_links)))
        except Exception as e:
            LOG.error("Failed to parse HTML {0}".format(e))
            return

        # Vist Each Article & Strip Intel



        all_data = {}


        for link in list_links:
            ip_list = []
            url_list = []
            filename_list = []
            email_list = []
            subject_list = []

            try:
                post_content = requests.get(link).text
                LOG.debug('Requesting content from {0}'.format(link))
            except Exception as e:
                LOG.error("Failed to get secondary request {0}".format(e))
                return

            try:
                # Email Subject
                email_subject = re.findall("Subject</b>:&nbsp;&nbsp;&nbsp;(.*?)(?=<)", post_content)
                for subject in email_subject:
                    subject_list.append(subject.strip())
            except Exception as e:
                LOG.error("Failed to get Email Subject {0}".format(e))

            try:
                # Malicious/Callback IP Address    
                ip_addr = re.findall('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', post_content)
                for ip in ip_addr:
                    ip_list.append(ip)
            except Exception as e:
                LOG.error("Failed to get IP Address {0}".format(e))

            try:
                # Sender Email Address
                email_addr = re.findall('([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', post_content)
                for email in email_addr:
                    email_list.append(email)
            except Exception as e:
                LOG.error("Failed to get Email Address {0}".format(e))

            try:
                # Attachment Name
                malicious_attachment = re.findall('>([a-zA-Z0-9_.+-]+.doc|.xls|.zip|.rar|.pdf)', post_content.lower())
                for attachment in malicious_attachment:
                    filename_list.append(attachment.strip())
            except Exception as e:
                LOG.error("Failed to get Attachment Name {0}".format(e))

            try:
                # Malicious/Callback URL
                malicious_url = re.findall('>([a-zA-Z0-9_.+-\/]+\/[a-zA-Z0-9_.+-\/]+.exe)', post_content.lower())
                for url in malicious_url:
                    url_list.append(url)
            except Exception as e:
                LOG.error("Failed to get URL {0}".format(e))

            all_data[link] = {'iplist': ip_list,
                              'urllist': url_list,
                              'filenamelist': filename_list,
                              'emaillist': email_list,
                              'subjectlist': subject_list
                              }
        
        # Return all the lists

        return all_data

    def _process_item(self, item):

        indicator_list = []

        # Convert to Dict
        item = dict(item)

        for key, values in item.iteritems():

            if self.output_type.lower() == 'ip':
                for ip in values['iplist']:
                    indicator = ip
                    value = {
                        'type': 'IPv4',
                        'confidence': 50,
                        'IP': ip,
                        'Report': key
                    }
                    indicator_list.append([indicator, value])

            if self.output_type.lower() == 'url':
                for url in values['urllist']:
                    indicator = url
                    value = {
                        'type': 'URL',
                        'confidence': 50,
                        'URL': url,
                        'Report': key
                    }
                    indicator_list.append([indicator, value])

            if self.output_type.lower() == 'file.name':
                for filename in values['filenamelist']:
                    indicator = filename
                    value = {
                        'type': 'file.name',
                        'confidence': 50,
                        'file.name': filename,
                        'Report': key
                    }
                    indicator_list.append([indicator, value])

            if self.output_type.lower() == 'email-addr':
                for email in values['emaillist']:
                    indicator = email
                    value = {
                        'type': 'email-addr',
                        'confidence': 50,
                        'email-addr': email,
                        'Report': key
                    }
                    indicator_list.append([indicator, value])
        return indicator_list
