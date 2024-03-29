using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Web;

namespace gt4_csharp_demo.Controllers
{
    [Route("/login")]
    public class IndexController : Controller
    {
        // geetest 公钥
        // geetest public key
        protected static string CAPTCHA_ID = "647f5ed2ed8acb4be36784e01556bb71";
        // geetest 密钥
        // geetest key
        protected static string CAPTCHA_KEY = "b09a7aafbfd83f73b35a9b530d0337bf";
        // geetest 服务地址
        // geetest service address
        protected static string API_SERVER = "http://gcaptcha4.geetest.com";
        // geetest 验证接口
        // geetest verification interface
        protected static string URL = API_SERVER + "/validate" + "?captcha_id=" + CAPTCHA_ID;

       [Route("")]
        public JsonResult Login()
        {
            // 前端参数
            // front end parameter
            string lot_number = Request.Query["lot_number"];
            string captcha_output = Request.Query["captcha_output"];
            string pass_token = Request.Query["pass_token"];
            string gen_time = Request.Query["gen_time"];

            // 生成签名 
            // generate signature
            // 生成签名使用标准的hmac算法，使用用户当前完成验证的流水号lot_number作为原始消息message，使用客户验证私钥作为key
            // use standard hmac algorithms to generate signatures, and take the user's current verification serial number lot_number as the original message, and the client's verification private key as the key
            // 采用sha256散列算法将message和key进行单向散列生成最终的 “sign_token” 签名
            // use sha256 hash algorithm to hash message and key in one direction to generate the final signature
            string sign_token = HmacSha256Encode(lot_number, CAPTCHA_KEY);

            // 向极验转发前端参数 + “sign_token” 签名
            // send front end parameter + "sign_token" signature to geetest
            IDictionary<string, string> paramDict = new Dictionary<string, string> { };
            paramDict.Add("lot_number", lot_number);
            paramDict.Add("captcha_output", captcha_output);
            paramDict.Add("pass_token", pass_token);
            paramDict.Add("gen_time", gen_time);
            paramDict.Add("sign_token", sign_token);

            // 返回json数据: {"result": "success", "reason": "", "captcha_args": {}}
            // return json data including {"result": "success", "reason": "", "captcha_args": {}}
            string resBody = HttpPost(URL, paramDict);

            if(resBody == null)
            {   
                // 当请求Geetest服务接口出现异常，应放行通过，以免阻塞正常业务。
                // when geetest server interface exceptions occur, the request should pass in order not to interrupt the website's business
                System.Diagnostics.Debug.WriteLine("geetest服务异常");
                return Json(new { result = "success" });
            }
            Dictionary<string, object> resDict = JsonSerializer.Deserialize<Dictionary<string, object>>(resBody);

            // 根据极验返回的用户验证状态, 网站主进行自己的业务逻辑
            // taking the user authentication status returned from geetest into consideration, the website owner follows his own business logic
            string result = (resDict["result"]).ToString();
            if (result == "success")
            {
                System.Diagnostics.Debug.WriteLine("校验成功");
            }
            else
            {
                System.Diagnostics.Debug.WriteLine("校验失败");
            }
            return Json(new { result = result });
        }

        // hmac-sha256 加密： lot_number，CAPTCHA_KEY
        // encrypt hmac-sha256: lot_number, CAPTCHA_KEY
        private string HmacSha256Encode(string value, string key)
        {
            using HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(key));
            byte[] data = hmac.ComputeHash(Encoding.UTF8.GetBytes(value));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < data.Length; i++)
            {
                sb.Append(data[i].ToString("x2"));
            }
            return sb.ToString();
        }

        // 发起post请求，选择贴合业务的http工具
        // initialize a post request to choose a http tool that suits the website's business
        private string HttpPost(string url, IDictionary<string, string> paramDict)
        {
            Stream reqStream = null;
            Stream resStream = null;
            try
            {
                StringBuilder paramStr = new StringBuilder();
                foreach (KeyValuePair<string, string> item in paramDict)
                {
                    if (!(string.IsNullOrWhiteSpace(item.Key) || string.IsNullOrWhiteSpace(item.Value)))
                    {
                        paramStr.AppendFormat("&{0}={1}", HttpUtility.UrlEncode(item.Key, Encoding.UTF8), HttpUtility.UrlEncode(item.Value, Encoding.UTF8));
                    }

                }
                byte[] bytes = Encoding.UTF8.GetBytes(paramStr.ToString().Substring(1));
                HttpWebRequest req = (HttpWebRequest)WebRequest.Create(url);
                req.Method = "POST";
                req.ContentType = "application/x-www-form-urlencoded";
                req.ReadWriteTimeout = 5000;
                req.Timeout = 5000;
                reqStream = req.GetRequestStream();
                reqStream.Write(bytes, 0, bytes.Length);
                HttpWebResponse res = (HttpWebResponse)req.GetResponse();

                resStream = res.GetResponseStream();
                StreamReader reader = new StreamReader(resStream, Encoding.GetEncoding("utf-8"));
                return reader.ReadToEnd();
            }
            catch (Exception e)
            {
                return null;
            }
            finally
            {
                if (reqStream != null)
                {
                    reqStream.Close();
                }
                if (resStream != null)
                {
                    resStream.Close();
                }
            }
        }
    }
}
