/*
 * Created by SharpDevelop.
 * User: Marlon
 * Date: 3/16/2016
 * Time: 1:32 PM
 * 
 * To change this template use Tools | Options | Coding | Edit Standard Headers.
 */
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Configuration;
using System.IO;
using System.Net;
using System.Web;
using System.Text;
using System.Collections.Specialized;
using RestSharp;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using System.Linq;

namespace Senior_Project
{
	/// <summary>
	/// Description of MainForm.
	/// </summary>
	public partial class MainForm : Form
	{
		string filePath = "";
		public MainForm()
		{
			//
			// The InitializeComponent() call is required for Windows Forms designer support.
			//
			InitializeComponent();
			
			//
			// TODO: Add constructor code after the InitializeComponent() call.
			//
		}
		
		void Button1Click(object sender, EventArgs e)
		{	
			textBox1.Clear();
			OpenFileDialog openFileDialog1 = new OpenFileDialog();
			openFileDialog1.Title = "Open File";
			
			if (openFileDialog1.ShowDialog() == System.Windows.Forms.DialogResult.OK)
			{
				filePath = openFileDialog1.FileName;
				
				MessageBox.Show(filePath);
			}
			
			textBox1.AppendText(filePath);
		}
		
		void Button2Click(object sender, EventArgs e)
		{
			/*using(WebClient client = new WebClient()) {
				System.Collections.Specialized.NameValueCollection reqparam = new System.Collections.Specialized.NameValueCollection();
				reqparam.Add("apikey", "ba3dd0bfaceb4191eff8a8e1dc673807d2a1eea1451074eef75afc7b78b344b6");
				reqparam.Add("file", filePath);
				
				
				byte[] responsebytes = client.UploadValues("https://www.virustotal.com/vtapi/v2/file/scan", "POST", reqparam);
				string responsebody = Encoding.UTF8.GetString(responsebytes);
				
				MessageBox.Show(responsebody);
			}*/
			//VirusTotal test = new VirusTotal("ba3dd0bfaceb4191eff8a8e1dc673807d2a1eea1451074eef75afc7b78b344b6");
			//test.GetResults(test.Scan(filePath));
			VirusTotal vtObject = new VirusTotal("ba3dd0bfaceb4191eff8a8e1dc673807d2a1eea1451074eef75afc7b78b344b6");
			//string resultID = vtObject.Scan(filePath);
			//string results = vtObject.GetResults(resultID);
			vtObject.Scan(filePath);
		}
	}
}

namespace Senior_Project
{
	public class VirusTotal
	{
    private string APIKey;
    //string scan = "https://www.virustotal.com/api/scan_file.json";
    string results = string.Empty;
    private string file_name = string.Empty;

    public VirusTotal(string apiKey)
    {
        ServicePointManager.Expect100Continue = false;
        APIKey = apiKey;
    }

    public void Scan(string fileName)
    {
        /*var v = new NameValueCollection();
        v.Add("key", APIKey);
        var c = new WebClient() { QueryString = v };
        c.Headers.Add("Content-type", "binary/octet-stream");
        byte[] b = c.UploadFile(scan, "POST", file);
        var r = ParseJSON(Encoding.Default.GetString(b));
        if (r.ContainsKey("scan_id"))
        {
            return r["scan_id"];
        }
        throw new Exception(r["result"]);*/
        
        this.file_name = fileName;
            NameValueCollection nvc = new NameValueCollection();
            nvc.Add("key", this.APIKey);
            nvc.Add("scan", "1");
            string r = httpUploadFile("https://www.virustotal.com/api/scan_file.json", this.file_name, "file", "application/exe", nvc);

            JObject o = JObject.Parse(r);
            string scan_id = (string)o["scan_id"];
            string[] s = scan_id.Split('-');
            getScanReport(s[0]);
    }

    public void getScanReport(string nResource)
    {
        /*Clipboard.SetText(id);
        var data = string.Format("resource={0}&key={1}", id, APIKey);
        var c = new WebClient();
        string s = c.UploadString(results, "POST", data);
        var r = ParseJSON(s);
        foreach (string str in r.Values)
        {
            MessageBox.Show(str);
        }
        if (r["result"] != "1")
        {
            throw new Exception(r["result"]);
        }
        return s;*/
        
        string r = this.httpPost("https://www.virustotal.com/api/get_file_report.json", "resource=" + nResource + "&key=" + this.APIKey);
            JObject o = JObject.Parse(r);
            foreach (JProperty jp in o["report"].Last)
            {
                this.results += jp.Name + "," + jp.First + "\n";
            }
            MessageBox.Show(results);
    }
    
    private string httpPost(string uri, string parms)
        {
            WebRequest req = WebRequest.Create(uri);
            
            req.ContentType = "application/x-www-form-urlencoded";
            req.Method = "POST";
            byte[] bytes = Encoding.ASCII.GetBytes(parms);
            Stream os = null;

            try
            {
                req.ContentLength = bytes.Length;
                os = req.GetRequestStream();
                os.Write(bytes, 0, bytes.Length);
            }
            catch (WebException ex)
            {
                MessageBox.Show(ex.Message, "Request error");
            }
            finally
            {
                if (os != null)
                {
                    os.Close();
                }
            }

            try
            {
                WebResponse webResponse = req.GetResponse();
                if (webResponse == null)
                { return null; }
                StreamReader sr = new StreamReader(webResponse.GetResponseStream());
                return sr.ReadToEnd().Trim();
            }
            catch (WebException ex)
            {
                MessageBox.Show(ex.Message, "Response error");
            }
            return null;
        }
    private string httpUploadFile(string url, string file, string paramName, string contentType, NameValueCollection nvc)
        {
            string ret = string.Empty;

            string boundary = "---------------------------" + DateTime.Now.Ticks.ToString("x");
            byte[] boundarybytes = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "\r\n");

            HttpWebRequest wr = (HttpWebRequest)WebRequest.Create(url);
            wr.ContentType = "multipart/form-data; boundary=" + boundary;
            wr.Method = "POST";
            wr.KeepAlive = true;
            wr.Credentials = System.Net.CredentialCache.DefaultCredentials;

            Stream rs = wr.GetRequestStream();
            string formdataTemplate = "Content-Disposition: form-data; name=\"{0}\"\r\n\r\n{1}";

            foreach (string key in nvc.Keys)
            {
                rs.Write(boundarybytes, 0, boundarybytes.Length);
                string formitem = string.Format(formdataTemplate, key, nvc[key]);
                byte[] formitembytes = System.Text.Encoding.UTF8.GetBytes(formitem);
                rs.Write(formitembytes, 0, formitembytes.Length);
            }

            rs.Write(boundarybytes, 0, boundarybytes.Length);
            string headerTemplate = "Content-Disposition: form-data; name=\"{0}\"; filename=\"{1}\"\r\nContent-Type: {2}\r\n\r\n";
            string header = string.Format(headerTemplate, paramName, file, contentType);
            byte[] headerbytes = System.Text.Encoding.UTF8.GetBytes(header);
            rs.Write(headerbytes, 0, headerbytes.Length);
            FileStream fileStream = new FileStream(file, FileMode.Open, FileAccess.Read);
            byte[] buffer = new byte[4096];
            int bytesRead = 0;

            while ((bytesRead = fileStream.Read(buffer, 0, buffer.Length)) != 0)
            {
                rs.Write(buffer, 0, bytesRead);
            }

            fileStream.Close();            
            byte[] trailer = System.Text.Encoding.ASCII.GetBytes("\r\n--" + boundary + "--\r\n");
            rs.Write(trailer, 0, trailer.Length);
            rs.Close();
            WebResponse wresp = null;

            try
            {
                wresp = wr.GetResponse();
                Stream stream2 = wresp.GetResponseStream();
                StreamReader reader2 = new StreamReader(stream2);
                ret = reader2.ReadToEnd();
            }
            catch (Exception ex)
            {
                if (wresp != null)
                {
                    wresp.Close();
                    wresp = null;
                }
            }
            finally
            {
                wr = null;
            }

            return ret;
        }

    private Dictionary<string, string> ParseJSON(string json)
    {
        var d = new Dictionary<string, string>();
        json = json.Replace("\"", null).Replace("[", null).Replace("]", null);
        var r = json.Substring(1, json.Length - 2).Split(',');
        foreach (string s in r)
        {
            d.Add(s.Split(':')[0], s.Split(':')[1]);
        }
        return d;
    }
}
}
