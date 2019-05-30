# 使用说明：
    爬取的绿盟科技RSAS v6.x扫描器漏洞库，可以拿来作为漏洞管理的知识库(目前更新到2019.5.30，后续看情况更新)
    仅为漏洞库(漏洞名称，漏洞描述，漏洞修复方案，漏洞各种ID等)
    非漏洞扫描规则(并不是拿来扫描漏洞的POC)

    vul_detail.sql为数据库导出数据
    config/config.json为配置文件，database为数据库配置，scanner为扫描器配置
    crawl_data.py 为运行主程序，使用时运行python3 crawl_data.py
    nsfocus_auth.py 为扫描器认证配置
    
    使用前请确保
        > 数据库及扫描器配置正确
        > 环境及python模块都有
        > 创建数据库及数据表

# 运行环境
    Linux + Python3

# python模块:
    PyMySQL
    beautifulsoup4
    requests

# 创建数据库
    CREATE DATABASE `gaea` /*!40100 DEFAULT CHARACTER SET utf8; 
    
# 创建数据表
    CREATE TABLE `vul_detail` (
      `vul_id` varchar(20) NOT NULL,
      `risk_level` varchar(20) DEFAULT NULL,
      `vul_name` varchar(200) NOT NULL DEFAULT '',
      `vul_desc` varchar(5000) DEFAULT NULL,
      `vul_solution` varchar(10000) DEFAULT NULL,
      `danger_point` varchar(20) DEFAULT NULL,
      `danger_plugin` varchar(20) DEFAULT NULL,
      `first_found` varchar(20) DEFAULT NULL,
      `cve_id` varchar(20) DEFAULT NULL,
      `cnnvd_id` varchar(20) DEFAULT NULL,
      `cncve_id` varchar(20) DEFAULT NULL,
      `bugtraq_id` varchar(20) DEFAULT NULL,
      `nsfocus_id` varchar(20) DEFAULT NULL,
      `cvss_point` varchar(20) DEFAULT NULL,
      `cnvd_id` varchar(20) DEFAULT NULL,
      `update_time` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (`vul_id`,`vul_name`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8; 

# 注意事项
    > 爬虫线程不宜设置过大，否则会导致扫描器Web界面无法连接。经测试线程为10的时候，扫描器打开缓慢，线程为20的时候，扫描器基本已经无法打开了； 
