# Qualys MCP — 560 Customer Questions by Category

Coverage key: ✅ Fully covered | ⚠️ Partially covered | ❌ Not covered

---

## Investigation Chaining (meta-tool)

1. ✅ Investigate CVE-2021-44228 (Log4Shell) completely — affected assets, patch status, exceptions
2. ✅ Give me a full deep-dive on why our TruRisk score increased this week
3. ✅ Investigate our ransomware exposure end-to-end
4. ✅ Do a complete investigation of asset server-prod-01
5. ⚠️ Tell me everything about CVE-2024-3400 and our exposure
6. ✅ Why is our risk score high? Give me the full picture
7. ✅ Investigate our compliance posture thoroughly
8. ⚠️ Chain: investigate Log4Shell → then show patch status for affected assets
9. ✅ Investigate this week's top vulnerability priorities in depth
10. ✅ Give me a complete cloud security investigation

---

## Vulnerability Management (VM) — 90 questions

### Daily operations
1. ✅ What new vulnerabilities were detected overnight?
2. ✅ What's my morning security summary?
3. ✅ What changed in my vulnerability posture this week?
4. ✅ What are my top 10 riskiest vulnerabilities right now?
5. ⚠️ Show me all vulnerabilities with active ransomware associations.
6. ✅ What vulnerabilities have public exploits available?
7. ✅ What zero-days are we currently exposed to?
8. ⚠️ Show me all Critical severity vulnerabilities detected in the last 7 days.
9. ✅ What's my overall vulnerability count by severity?
10. ✅ How many High/Critical vulns do I have that aren't patched?

### CVE investigation
11. ✅ Are we affected by Log4Shell (CVE-2021-44228)?
12. ✅ How many assets are vulnerable to CVE-2024-3400?
13. ✅ What's the patch for CVE-2023-4966?
14. ✅ Is CVE-2021-34527 (PrintNightmare) still in our environment?
15. ✅ Tell me about CVE-2024-1234 — severity, assets, patches.
16. ✅ Compare these 5 CVEs — which is most critical for us?
17. ✅ Does CVE-2023-44487 (HTTP/2 Rapid Reset) affect any of my servers?
18. ✅ What Qualys QIDs are associated with CVE-2024-21413?
19. ✅ Which CVEs have CVSS score above 9.0 in my environment?
20. ✅ What CVEs are in the CISA KEV list and affecting us?

### QID lookups
21. ✅ What is QID 105233 and which assets have it?
22. ✅ Show me all assets affected by QID 376267.
23. ✅ What's the severity and category of QID 91360?
24. ✅ Does QID 91812 have a patch available?
25. ✅ What software does QID 150001 affect?
26. ✅ Show me all QIDs for remote code execution vulnerabilities.
27. ✅ What QIDs were added to the Qualys KB this week?
28. ⚠️ Show me all QIDs in my environment above QDS 90.
29. ⚠️ Which QIDs affect Windows Server 2019 specifically?
30. ❌ What's the remediation deadline for QID 90007 based on our SLA?

### Severity and aging
31. ✅ How many Critical vulnerabilities have been open more than 30 days?
32. ⚠️ What vulnerabilities have been open the longest?
33. ⚠️ Show me vulnerabilities that have aged past our SLA.
34. ❌ What's our mean time to remediate by severity?
35. ❌ Show me a trend: new vulns detected vs closed over the past 30 days.
36. ❌ How has our Critical vulnerability count changed month over month?
37. ⚠️ What's our remediation rate for the past quarter?
38. ❌ Which teams have the highest average vulnerability age?
39. ❌ What percentage of our vulnerabilities are within SLA?
40. ❌ Show me the vulnerability backlog trend for the last 6 months.

### Software-specific
41. ✅ What vulnerabilities affect Apache HTTPD in our environment?
42. ✅ Show me all Windows vulnerabilities.
43. ✅ What OpenSSL vulnerabilities do we have?
44. ✅ Show me all vulnerabilities affecting Internet Explorer.
45. ✅ What vulns affect Adobe Acrobat across our fleet?
46. ✅ How many assets have vulnerable versions of log4j?
47. ✅ What Microsoft Office vulnerabilities are in our environment?
48. ✅ Show me all VMware ESXi vulnerabilities.
49. ✅ What Chrome and Edge vulnerabilities are outstanding?
50. ✅ Are any of our assets running vulnerable Java versions?

### Risk scoring
51. ✅ What's our TruRisk score today?
52. ✅ Which assets have the highest TruRisk scores?
53. ✅ What's the TruRisk distribution across our environment?
54. ✅ How does our TruRisk compare to industry benchmarks?
55. ⚠️ Which business groups have the highest aggregate TruRisk?
56. ⚠️ What drove the change in our TruRisk score this week?
57. ❌ Show me TruRisk trend for the past 90 days.
58. ❌ What's the TruRisk score for the "Production Servers" asset group?
59. ❌ Which asset tags have the worst TruRisk scores?
60. ❌ How does removing our top 10 vulns affect our overall TruRisk?

### Detection and scanning
61. ✅ Are all my assets being scanned regularly?
62. ✅ Which scanners are offline or degraded?
63. ✅ When was each asset last scanned?
64. ⚠️ Which assets haven't been scanned in the last 30 days?
65. ⚠️ What's the scan coverage for my cloud assets?
66. ✅ Show me running and queued scans right now.
67. ✅ What scans failed in the last 24 hours?
68. ✅ How long did yesterday's scan take?
69. ❌ What's the scan schedule for the Production network?
70. ❌ Which scan options profiles are being used and by whom?

### Remediation tracking
71. ✅ What's our patching coverage percentage?
72. ✅ Which assets are missing critical patches?
73. ✅ What are the top 5 patches that would reduce the most risk?
74. ✅ Which assets have the most outstanding vulnerabilities?
75. ✅ Show me all accepted risk (exception) vulnerabilities.
76. ✅ What vulnerabilities have been marked as false positives?
77. ✅ How many vulnerabilities have active exceptions/waivers?
78. ✅ Which exceptions are about to expire?
79. ⚠️ What's our false positive rate?
80. ⚠️ Show me all vulnerabilities in "Ignored" state.

### Reporting
81. ⚠️ Generate a vulnerability summary report for my CISO.
82. ⚠️ What's our top 10 list for the weekly security standup?
83. ✅ What should my team focus on this week?
84. ✅ Give me an executive summary of our security posture.
85. ⚠️ What are our top 3 risk reduction opportunities?
86. ❌ Export all Critical vulns to a spreadsheet format.
87. ❌ Show me vulnerability metrics broken down by business unit.
88. ❌ What's the vulnerability density per asset by department?
89. ❌ Generate a board-level security risk summary.
90. ❌ What's our patch SLA compliance rate by severity tier?

---

## Patch Management (PM) — 50 questions

### Job status
91. ✅ What's the status of our current patching jobs?
92. ✅ How many patches are deployed vs missing?
93. ✅ What Windows patches are outstanding?
94. ✅ Show me the latest patch deployment job results.
95. ⚠️ What patches failed to deploy in the last week?
96. ❌ Show me all active patch deployment jobs.
97. ❌ What's the status of patch job ID 12345?
98. ❌ Which assets are in scope for the current patch cycle?
99. ❌ Show me the history of patch deployments for asset X.
100. ❌ Which jobs have been running longer than expected?

### Patch coverage
101. ✅ What's our overall patch coverage percentage?
102. ✅ How many assets are missing critical patches?
103. ✅ What critical patches are outstanding for Windows?
104. ⚠️ Show me patch coverage by operating system.
105. ⚠️ Which Linux systems are missing security patches?
106. ❌ What's our patch coverage for macOS assets?
107. ❌ Show me patch success rate by patch job.
108. ❌ What percentage of systems applied last month's Patch Tuesday?
109. ❌ Which systems repeatedly fail to patch?
110. ❌ What's our mean time to patch by severity?

### Specific patches
111. ⚠️ Is the Microsoft Patch Tuesday bundle from this month deployed?
112. ❌ Show me all assets that need KB5031361.
113. ❌ Which third-party application patches are outstanding?
114. ❌ What patches address the current CISA KEV vulnerabilities?
115. ❌ Show me all patches for the Adobe Acrobat vulnerability.
116. ❌ What Linux kernel patches are available and not yet deployed?
117. ❌ Which patches have been superseded?
118. ❌ Show me patches by vendor: Microsoft, Adobe, Google.
119. ❌ What patches are available for my Java installations?
120. ❌ How many QIDs does installing patch KB5030211 fix?

### Exceptions and scheduling
121. ❌ Which assets have patch exceptions?
122. ❌ Show me all maintenance windows for patching.
123. ❌ When is the next scheduled patch deployment?
124. ❌ Which assets are excluded from patching?
125. ❌ What's the reason for the patch exception on server-XYZ?
126. ❌ Show me patches that have been deferred more than 60 days.
127. ❌ Which assets are in patch exclusion groups?
128. ❌ What's the rollback history for patch jobs?
129. ❌ Show me all patch jobs in the last 30 days.
130. ❌ Which patch jobs are scheduled for this weekend?

### Reporting
131. ⚠️ What's our monthly patching report?
132. ❌ Show me patch compliance by department/team.
133. ❌ What's our Patch Tuesday response time historically?
134. ❌ Which teams have the worst patch coverage?
135. ❌ Show me a patch velocity trend for the past 6 months.
136. ❌ What's the risk reduction from our last patch cycle?
137. ❌ How many CVEs were addressed by last month's patches?
138. ❌ Generate a patch management executive summary.
139. ❌ What percentage of CRITICAL patches are within SLA?
140. ❌ Show me patch coverage against CIS benchmark requirements.

---

## TruRisk Eliminate — 30 questions

141. ✅ What's the status of our TruRisk Eliminate program?
142. ✅ Show me all active mitigation jobs.
143. ✅ What's the patch job queue in Eliminate?
144. ✅ How many vulnerabilities have been mitigated vs patched?
145. ✅ What's covered in our mitigation catalog?
146. ✅ Are there any failed mitigation jobs?
147. ✅ What vulnerabilities can be eliminated without patching?
148. ✅ Show me all in-progress patch jobs in Eliminate.
149. ✅ What's the success rate of our Eliminate patch deployments?
150. ⚠️ Which assets are targeted by current Eliminate jobs?
151. ✅ What mitigation techniques are being used (registry, config, etc.)?
152. ✅ Show me the Eliminate catalog coverage for our top 50 vulns.
153. ✅ Which vulnerabilities in our backlog have Eliminate mitigations?
154. ✅ How many QIDs does our current Eliminate catalog cover?
155. ❌ What's the historical Eliminate job completion rate?
156. ❌ Which Eliminate jobs failed and why?
157. ❌ Show me Eliminate job results for the last 30 days.
158. ❌ What's the risk reduction from our Eliminate program?
159. ❌ Which assets are onboarded to Eliminate?
160. ❌ Show me the mitigation vs patch breakdown for our top risks.
161. ⚠️ What new mitigations were added to the catalog this month?
162. ❌ Which vulnerabilities have only mitigation options (no patch)?
163. ❌ What's our Eliminate coverage vs traditional patching?
164. ❌ Show me Eliminate activity for the past week.
165. ❌ Which teams are using Eliminate vs traditional patching?
166. ❌ What's the average time from detection to Eliminate mitigation?
167. ❌ How does Eliminate reduce our overall TruRisk score?
168. ❌ Show me all patchless protection controls applied.
169. ❌ Which critical vulnerabilities can be eliminated without a reboot?
170. ❌ What's the ROI of our Eliminate program?

---

## Cloud Security (CSPM / CDR / TotalCloud) — 70 questions

### Cloud posture
171. ✅ What's our cloud security posture across AWS, Azure, and GCP?
172. ✅ What are our top cloud misconfigurations?
173. ✅ How many CIS benchmark controls are failing in AWS?
174. ✅ Which cloud accounts have the most security issues?
175. ✅ Show me all failed cloud controls for our Azure subscription.
176. ✅ What's our cloud compliance pass rate?
177. ⚠️ Which S3 buckets are publicly accessible?
178. ⚠️ Are any of our cloud storage accounts exposed to the internet?
179. ⚠️ Which cloud IAM policies grant excessive permissions?
180. ⚠️ Are any cloud resources missing encryption?
181. ⚠️ Which cloud security groups allow unrestricted inbound access?
182. ❌ Show me cloud compliance by account and region.
183. ❌ What's the trend in cloud security posture over the past month?
184. ❌ Which cloud resources are not tagged properly?
185. ❌ What's our cloud security score by provider (AWS/Azure/GCP)?
186. ❌ Show me all resources failing the "encryption at rest" control.
187. ❌ Which cloud accounts have MFA disabled for root?
188. ❌ Are any cloud VMs running without endpoint protection?
189. ❌ Show me cloud resources with open RDP or SSH ports.
190. ❌ What cloud assets have no backups configured?

### Cloud Detection & Response (CDR)
191. ✅ What cloud threats were detected in the last 7 days?
192. ✅ Show me all critical CDR findings in AWS.
193. ✅ Are there any crypto-mining activities detected in our cloud?
194. ✅ What malware was detected in cloud workloads this week?
195. ✅ Show me C2 callback attempts from our cloud VMs.
196. ✅ What lateral movement was detected in our cloud?
197. ✅ Are there any ransomware indicators in our cloud environment?
198. ✅ Show me CDR findings by category.
199. ⚠️ What external IPs are communicating with our cloud workloads?
200. ⚠️ Which CDR findings involve data exfiltration attempts?
201. ❌ Show me CDR findings for a specific EC2 instance.
202. ❌ What's the CDR trend over the past 30 days?
203. ❌ Which cloud accounts have the most CDR alerts?
204. ❌ Show me all CDR findings with CVE associations.
205. ❌ What CDR findings involved privilege escalation?

### Cloud connectors and inventory
206. ⚠️ How many cloud connectors are configured and healthy?
207. ⚠️ Which cloud connectors are failing?
208. ❌ Show me all connected AWS accounts.
209. ❌ What Azure subscriptions are monitored?
210. ❌ Which GCP projects are connected to Qualys?
211. ❌ Are there any cloud accounts without connectors?
212. ❌ When was the last cloud evaluation run?
213. ❌ Show me the cloud asset inventory by provider.
214. ❌ How many cloud VMs are we monitoring?
215. ❌ Which cloud resources are new this week?

### Compliance frameworks
216. ❌ What's our CIS AWS Benchmark score?
217. ❌ Show me our Azure CIS compliance percentage.
218. ❌ What's our GCP CIS compliance pass rate?
219. ❌ Which cloud resources fail PCI-DSS cloud controls?
220. ❌ What SOC 2 relevant cloud controls are failing?
221. ❌ Show me our NIST CSF cloud compliance status.
222. ❌ Which HIPAA cloud controls are we failing?
223. ❌ What cloud controls map to ISO 27001?
224. ❌ Show me cloud compliance trend by framework.
225. ❌ Which cloud accounts need remediation to achieve CIS Level 1?

### Cloud-specific
226. ❌ What AWS Lambda functions have excessive permissions?
227. ❌ Which RDS instances are publicly accessible?
228. ❌ Are any Kubernetes clusters exposed without authentication?
229. ❌ What cloud load balancers are missing TLS?
230. ❌ Which cloud functions have hardcoded credentials?
231. ❌ Are any cloud snapshots shared publicly?
232. ❌ Show me all internet-facing cloud resources.
233. ❌ Which cloud services have logging disabled?
234. ❌ What cloud resources have default credentials?
235. ❌ Are any cloud key management services misconfigured?
236. ❌ Show me all cloud resources in non-compliant regions.
237. ❌ Which cloud resources are missing network segmentation?
238. ❌ Are any auto-scaling groups misconfigured?
239. ❌ What cloud secrets are exposed in environment variables?
240. ❌ Which cloud VMs are missing vulnerability scanning?

---

## Container Security — 40 questions

### Image vulnerabilities
241. ✅ What vulnerabilities are in our production container images?
242. ✅ Show me all Critical vulns in the nginx:latest image.
243. ✅ Which container images have the most vulnerabilities?
244. ✅ Are any of our container images affected by Log4Shell?
245. ✅ What's the severity breakdown for image ID abc123?
246. ✅ Which container images are unpatched for more than 30 days?
247. ⚠️ Show me all container images from our production registry.
248. ⚠️ Which images are based on EOL base OS versions?
249. ⚠️ What's the vulnerability trend for our container fleet?
250. ❌ Which container images are newly scanned this week?
251. ❌ Show me images sorted by risk score.
252. ❌ Which images have critical vulns with public exploits?
253. ❌ What registries are we scanning?
254. ❌ Are there images in our registry that have never been scanned?
255. ❌ Show me vulnerability counts by image repository.

### Runtime and container inventory
256. ⚠️ What containers are currently running in production?
257. ⚠️ Show me all running containers with unpatched critical vulns.
258. ⚠️ Which containers have been running the longest?
259. ❌ Show me all container hosts and their running containers.
260. ❌ What new containers were deployed this week?
261. ❌ Which containers are running as root?
262. ❌ Show me all containers with privileged mode enabled.
263. ❌ Which container images are used in more than 10 running containers?
264. ❌ Show me containers with network ports exposed externally.
265. ❌ What's the average vulnerability count per running container?

### Kubernetes and orchestration
266. ❌ What Kubernetes clusters are being monitored?
267. ❌ Which K8s namespaces have the most vulnerable containers?
268. ❌ Are any Kubernetes workloads running with excessive RBAC permissions?
269. ❌ Show me all pods running images with Critical CVEs.
270. ❌ What Kubernetes misconfigurations are detected?
271. ❌ Which K8s deployments have the highest risk?
272. ❌ Are any containers missing resource limits?
273. ❌ Show me K8s pods with host network access.
274. ❌ Which Kubernetes secrets are improperly configured?
275. ❌ What's our Kubernetes CIS benchmark compliance rate?

### Container compliance
276. ❌ Which container images pass our security gate policy?
277. ❌ What's our container image pass rate in the CI/CD pipeline?
278. ❌ Which images would fail our vulnerability threshold policy?
279. ❌ Show me container compliance by team/project.
280. ❌ What's the container vulnerability SLA compliance rate?

---

## Web Application Security (WAS / TAS) — 50 questions

### WAS findings
281. ✅ What web application vulnerabilities were found this week?
282. ✅ Show me all OWASP Top 10 findings across our apps.
283. ✅ Which web apps have the most critical vulnerabilities?
284. ✅ Are any of our web applications vulnerable to SQL injection?
285. ✅ Show me all XSS vulnerabilities across our app portfolio.
286. ⚠️ What authentication flaws were detected in our web apps?
287. ✅ Which web apps have unpatched Critical vulnerabilities?
288. ✅ Show me all WAS findings for app "customer-portal".
289. ⚠️ What API security issues were detected?
290. ⚠️ Are there any CSRF vulnerabilities in our web apps?
291. ⚠️ Show me all sensitive data exposure findings.
292. ⚠️ Which web apps have broken access control issues?
293. ⚠️ What security misconfigurations were found in our web apps?
294. ✅ Show me all new WAS findings from the last scan.
295. ⚠️ Which web applications are most at risk?

### Scan management
296. ❌ When was each web application last scanned?
297. ❌ Which web apps haven't been scanned in 30+ days?
298. ❌ Show me WAS scan status for the last 7 days.
299. ❌ Which web app scans failed or errored?
300. ❌ What web apps are in scope for scanning?
301. ❌ How long does each web application scan take?
302. ❌ Show me scan coverage across our web application portfolio.
303. ❌ Which web apps are scanned with authentication?
304. ❌ What WAS scan profiles are configured?
305. ❌ Are there web applications in production not being scanned?

### DAST findings
306. ⚠️ What OWASP A01 broken access control findings do we have?
307. ⚠️ Show me all cryptographic failures (OWASP A02).
308. ⚠️ Which apps have injection vulnerabilities (OWASP A03)?
309. ⚠️ Are any apps running vulnerable components (OWASP A06)?
310. ⚠️ What server-side request forgery (SSRF) vulnerabilities exist?

### API security
311. ❌ Which APIs are exposed without authentication?
312. ❌ Show me all API endpoints with security issues.
313. ❌ Are any APIs exposing sensitive data?
314. ❌ Which APIs have excessive data exposure findings?
315. ❌ Show me broken object level authorization (BOLA) findings.

### Remediation
316. ❌ Which web vulnerabilities have been open the longest?
317. ❌ What's the WAS remediation rate this quarter?
318. ❌ Which developers own the most unpatched web vulnerabilities?
319. ❌ Show me WAS findings that map to CVEs.
320. ❌ What web vulnerabilities could lead to data breach?
321. ❌ Which web app findings are marked as accepted risk?
322. ❌ Show me WAS trend data for the past 90 days.
323. ❌ Which web app findings are in the OWASP Top 10?
324. ❌ What's our WAS finding severity distribution?
325. ❌ Which web applications have the highest risk scores?

### Compliance and reporting
326. ❌ Are our web apps compliant with PCI-DSS requirement 6.6?
327. ❌ What GDPR-relevant web vulnerabilities exist?
328. ❌ Generate a web application security report for our dev team.
329. ❌ What's our web application vulnerability trend?
330. ❌ How many web vulnerabilities were remediated this month?

---

## Endpoint / EDR — 35 questions

### EDR detections
331. ✅ What malware was detected on endpoints this week?
332. ✅ Show me all ransomware detections in the last 30 days.
333. ✅ Which endpoints have active threat detections?
334. ✅ Are any hosts showing signs of C2 communication?
335. ✅ What suspicious process executions were detected?
336. ✅ Show me all high severity EDR alerts.
337. ✅ Which endpoints have had the most security events?
338. ✅ Are there any lateral movement indicators on our network?
339. ⚠️ What credential theft attempts were detected?
340. ⚠️ Show me all privilege escalation events in the last 7 days.
341. ⚠️ Which user accounts are involved in suspicious activity?
342. ✅ Show me all EDR events for host "DESKTOP-ABC123".
343. ⚠️ What persistence mechanisms have been detected?
344. ⚠️ Are any endpoints showing signs of cryptominer activity?
345. ❌ What's the EDR detection trend over the past month?

### File Integrity Monitoring (FIM)
346. ✅ What file changes were detected in the last 24 hours?
347. ✅ Which critical system files were modified?
348. ✅ Show me all FIM events on production servers.
349. ⚠️ Were any configuration files changed outside maintenance windows?
350. ✅ Which hosts have the most file integrity events?
351. ✅ Show me all FIM events for /etc/passwd and /etc/shadow.
352. ⚠️ Are there unauthorized changes to Windows registry keys?
353. ⚠️ What FIM events occurred on weekend/off-hours?
354. ⚠️ Show me all FIM events involving executables.
355. ⚠️ Which FIM events are confirmed as suspicious?
356. ⚠️ What new files were created in system directories?
357. ✅ Show me FIM events filtered by path or file type.
358. ❌ Which servers have FIM monitoring enabled?
359. ❌ What's the FIM event volume trend?
360. ❌ Show me FIM events correlated with vulnerability detections.
361. ❌ Are there any FIM events matching known malware hashes?
362. ❌ What FIM events involve known attack paths?
363. ⚠️ Show me all FIM events by user account.
364. ⚠️ Which FIM monitored paths have the most activity?
365. ❌ What's the FIM policy coverage across our endpoint fleet?

---

## Certificates / CertView — 30 questions

### Expiry monitoring
366. ✅ Which SSL/TLS certificates expire in the next 30 days?
367. ✅ Show me all certificates expiring this month.
368. ✅ Which certificates expire in the next 90 days?
369. ✅ Are any certificates already expired?
370. ✅ Which production systems have expiring certificates?
371. ⚠️ Show me all wildcard certificates and their expiry dates.
372. ⚠️ Which certificate authorities issued our certificates?
373. ✅ Are there any self-signed certificates in production?
374. ⚠️ Show me all certificates by domain.
375. ❌ Which certificates were renewed this month?

### Weak ciphers and configuration
376. ✅ Which servers are using weak cipher suites (e.g., RC4, DES)?
377. ✅ Are any servers still using TLS 1.0 or 1.1?
378. ⚠️ Show me all servers with SSL vulnerabilities (POODLE, BEAST, etc.).
379. ✅ Which certificates use weak key algorithms (RSA < 2048)?
380. ❌ Are any servers missing HSTS headers?
381. ⚠️ Which servers have certificate chain issues?
382. ✅ Show me all certificates with SHA-1 signatures.
383. ⚠️ Are any certificates from untrusted CAs?
384. ❌ Which servers support insecure renegotiation?
385. ✅ Show me all TLS configuration issues across our web servers.

### Certificate inventory
386. ✅ How many SSL certificates do we have in total?
387. ⚠️ Show me the certificate inventory for our web application portfolio.
388. ⚠️ Which domains have multiple certificates?
389. ❌ Are there any duplicate certificates?
390. ✅ Show me all certificates sorted by expiry date.
391. ⚠️ Which internal systems have valid certificates?
392. ⚠️ Show me certificates by issuing CA.
393. ❌ How many certificates were issued in the last 90 days?
394. ❌ Which certificates are about to hit their maximum validity?
395. ❌ Show me certificates with mismatched hostnames.

---

## Asset Management (CSAM) — 40 questions

### Asset inventory
396. ✅ How many assets do we have in total?
397. ✅ How many end-of-life systems are in our environment?
398. ✅ Which assets are running EOL operating systems?
399. ✅ Show me all Windows Server 2012 R2 systems (EOL).
400. ✅ What's the breakdown of my assets by OS type?
401. ⚠️ How many assets have been added in the last 30 days?
402. ✅ Which assets are in the "Production" tag group?
403. ⚠️ Show me all assets with no vulnerability scans.
404. ✅ What asset tags do we have configured?
405. ⚠️ Show me all assets without any tags assigned.
406. ❌ How many assets are in each business unit?
407. ❌ Which assets are classified as critical/high business impact?
408. ⚠️ Show me all assets discovered in the last 7 days.
409. ⚠️ What cloud assets are in our inventory?
410. ❌ How does our asset count compare to last quarter?

### EOL and tech debt
411. ✅ What EOL hardware do we have?
412. ✅ Which systems are past end-of-support?
413. ✅ How many Windows 10 systems will hit EOL soon?
414. ✅ Show me all EOL software versions in our environment.
415. ⚠️ What's the total cost risk from EOL systems?
416. ⚠️ Which EOL systems are internet-facing?
417. ❌ Show me EOL systems by business unit.
418. ❌ What's the EOL timeline for our current OS fleet?
419. ❌ Which EOL systems are running critical business applications?
420. ❌ Show me a plan to migrate off EOL systems by priority.

### Asset search and filtering
421. ✅ Find all assets with hostname containing "prod".
422. ⚠️ Show me all assets in the 10.0.0.0/8 subnet.
423. ✅ Which assets have a specific software installed?
424. ⚠️ Find assets by owner or business unit tag.
425. ⚠️ Show me assets that are internet-facing.
426. ✅ Which assets haven't been seen in 30+ days?
427. ⚠️ Show me all virtual machines.
428. ⚠️ Find assets by criticality score.
429. ⚠️ Which assets are in our DMZ?
430. ❌ Show me all assets with a specific port open.

### Asset lifecycle
431. ❌ Which assets are scheduled for decommission?
432. ❌ Show me assets with no owner assigned.
433. ❌ Which assets have changed hardware configuration recently?
434. ❌ Show me all assets added to the network this week.
435. ❌ Which assets are duplicates (same IP, different hostname)?

---

## Compliance — 45 questions

### Policy compliance
436. ✅ What's our CIS Benchmark compliance score?
437. ✅ Show me all failing CIS controls for Windows Server.
438. ✅ What's our policy compliance rate for Linux systems?
439. ✅ Which systems are failing the most compliance checks?
440. ✅ What's our PCI-DSS compliance status?
441. ✅ Show me all failing PCI-DSS controls.
442. ⚠️ What's our HIPAA technical control compliance rate?
443. ✅ Show me compliance failures by severity.
444. ⚠️ What's our SOC 2 relevant control pass rate?
445. ⚠️ Which systems fail the NIST 800-53 controls?
446. ⚠️ Show me our ISO 27001 compliance gaps.
447. ❌ What FedRAMP controls are we failing?
448. ❌ Show me DISA STIG compliance for our network devices.
449. ❌ What's our compliance pass rate trend over the last quarter?
450. ❌ Which asset groups have the worst compliance posture?

### Specific controls
451. ❌ Which systems have password policies that don't meet standards?
452. ❌ Are any systems missing disk encryption?
453. ❌ Which hosts have insecure remote access configured (Telnet, FTP)?
454. ❌ Are any systems with default credentials detected?
455. ❌ Which systems are missing security logging?
456. ❌ Are antivirus definitions up to date on all systems?
457. ❌ Which systems have unnecessary services running?
458. ❌ Are any accounts with admin rights that shouldn't have them?
459. ❌ Which systems have USB storage enabled?
460. ❌ Are any systems missing host-based firewalls?

### Compliance by framework
461. ❌ Generate a CIS benchmark compliance report.
462. ❌ What's our PCI-DSS scope and compliance posture?
463. ❌ Show me HIPAA technical safeguard compliance gaps.
464. ❌ Which controls does Qualys map to SOC 2 Type II criteria?
465. ❌ What ISO 27001 Annex A controls are covered by Qualys?
466. ❌ Show me NIST Cybersecurity Framework coverage.
467. ❌ What's our compliance status for GDPR technical requirements?
468. ❌ Show me our CMMC compliance gaps.
469. ❌ What Essential 8 maturity level are we at?
470. ❌ Show me compliance failures that could result in audit findings.

### Remediation and exceptions
471. ❌ Which compliance failures have accepted exceptions?
472. ❌ What's the remediation plan for our top compliance gaps?
473. ❌ Which compliance controls have the most failing assets?
474. ❌ Show me compliance trend: improving or degrading?
475. ❌ Which exceptions expire this month?
476. ❌ What's the compliance impact of patching our top 10 vulns?
477. ❌ Show me compensating controls for compliance failures.
478. ❌ Which systems have repeated compliance failures?
479. ❌ What compliance waivers are approved vs pending?
480. ❌ Generate a compliance exception report for auditors.

---

## Scanner / Infrastructure — 20 questions

481. ✅ Are all my scanners healthy?
482. ✅ Which scanners are offline?
483. ✅ When did each scanner last check in?
484. ✅ Which scanners have outdated vulnerability signatures?
485. ✅ What's the scan load on each scanner appliance?
486. ✅ Which scanners have failed scans?
487. ✅ Show me all running scans right now.
488. ✅ What scans are queued?
489. ✅ Show me scan history for the last 7 days.
490. ❌ Which networks have no scan coverage?
491. ❌ What's the scan duration trend?
492. ⚠️ Show me all external vs internal scans.
493. ❌ Which scan option profiles are used most?
494. ⚠️ What scan targets are configured?
495. ❌ Which scans ran after hours?
496. ❌ Show me authenticated vs unauthenticated scan results.
497. ⚠️ Which scanners are close to capacity?
498. ❌ What's the scan frequency for each asset group?
499. ❌ Show me all scheduled scans and their next run time.
500. ⚠️ Which scans have never completed successfully?

## Growth Engine — 5 questions

### Next actions and gap detection
501. ✅ When I get my morning report, does it include suggested next investigation steps in a _next block?
502. ✅ Does the morning report detect coverage gaps like missing EDR, FIM, or cloud posture and show them in a _gaps field?
503. ✅ Summarize these investigation findings for an executive audience: {"topic":"CVE-2024-3400","risk_level":"critical","key_facts":["Severity 5/5","100 assets affected"],"recommended_actions":["Deploy patch immediately"]}

### Audience-specific summaries
504. ✅ Summarize this investigation for a technical audience with full QID and CVE details: {"cve":"CVE-2021-44228","qids":[376160],"severity":5,"qds":95,"ransomware":true}
505. ⚠️ Does calling get_morning_report write a usage log entry to ~/.qualys-mcp/usage.jsonl when QUALYS_MCP_NO_TRACKING is not set?

---

## 2026 Threat Landscape — 55 questions

### Recent high-impact CVEs
506. ⚠️ Are we affected by CVE-2024-3400 (PAN-OS command injection)? Show all vulnerable Palo Alto devices.
507. ⚠️ What's our exposure to CVE-2024-6387 (regreSSHion)? List all OpenSSH servers at risk.
508. ⚠️ How many assets are vulnerable to CVE-2024-21762 (FortiOS out-of-bound write)?
509. ⚠️ Are any of our JetBrains TeamCity instances affected by CVE-2024-27198 (auth bypass)?
510. ⚠️ Do we have ASUS routers vulnerable to CVE-2024-3080 (authentication bypass)?
511. ⚠️ What's our patch status for CVE-2024-3400 across all PAN-OS firewalls?
512. ⚠️ Show me all assets still vulnerable to regreSSHion after the latest patch cycle.
513. ⚠️ Which FortiGate devices are missing the fix for CVE-2024-21762?
514. ⚠️ Are there any CVE-2024-27198 exploits detected in our environment?
515. ⚠️ Give me a timeline of when CVE-2024-3400 was first detected vs when we patched.

### Zero-day response workflows
516. ⚠️ Which newly disclosed CVEs (last 30 days) affect our most critical assets?
517. ⚠️ Show me all assets vulnerable to CVEs with active exploit code — sorted by asset criticality.
518. ⚠️ What's our average time-to-detect for critical vulnerabilities published in 2024?
519. ⚠️ Which assets were newly found vulnerable in the last scan cycle?
520. ⚠️ Show me all unpatched CVEs with CVSS v3 ≥9.0 affecting internet-facing systems.
521. ⚠️ What percentage of CVEs with active exploits are remediated within 30 days?
522. ⚠️ List vulnerabilities discovered more than 90 days ago that are still unpatched on critical systems.

### TruRisk and risk prioritization
523. ⚠️ What's our current overall TruRisk score and how has it changed this month?
524. ⚠️ Which asset groups or business units have the highest TruRisk scores?
525. ⚠️ Show me the top 10 vulnerabilities by TruRisk contribution across our estate.
526. ⚠️ Which internet-facing assets have TruRisk scores above the critical threshold?
527. ⚠️ What's our TruRisk trend over the past 90 days — are we improving or regressing?
528. ⚠️ Show me assets with TruRisk scores in the critical range and their open vulnerability count.
529. ⚠️ Which remediation actions would most significantly reduce our TruRisk score?

### Supply chain and container provenance
530. ⚠️ Which container images running in production have critical CVEs in their base OS layers?
531. ⚠️ Show me all containers pulled from public registries with known vulnerable packages.
532. ⚠️ Which deployed container images haven't been rebuilt or updated in over 90 days?
533. ⚠️ Are any containers running with root privileges and known privilege escalation CVEs?
534. ⚠️ Show me our container vulnerability density compared to VM/host vulnerability density.
535. ⚠️ Which container base images (ubuntu, debian, alpine) have the most unpatched CVEs?
536. ⚠️ What's our software supply chain risk — which third-party packages have the most active CVEs?

### AI and LLM security posture
537. ❌ Do we have any AI/ML model serving endpoints exposed to the internet?
538. ❌ Are there any known vulnerabilities in our deployed LLM frameworks (LangChain, vLLM, etc.)?
539. ❌ Show me all assets running AI inference services and their patch status.
540. ❌ What's our attack surface for prompt injection and LLM-specific vulnerabilities?
541. ❌ Are any of our AI model APIs accessible without authentication?
542. ❌ Which GPU-enabled instances have unpatched CUDA or driver vulnerabilities?
543. ❌ Do we have visibility into AI supply chain dependencies (model registries, training data stores)?

### Cloud-native attack patterns
544. ⚠️ Are any of our cloud workloads vulnerable to SSRF attacks?
545. ⚠️ Show me all container images with known supply chain vulnerabilities (compromised base images).
546. ⚠️ Which Kubernetes pods can escape to the host via known container escape CVEs?
547. ⚠️ Do we have any S3 buckets or Azure Blob containers with public access and sensitive data?
548. ⚠️ Are there any IAM roles with overly permissive policies that could enable lateral movement?
549. ⚠️ Show me all cloud workloads missing runtime protection agents.
550. ⚠️ Which CI/CD pipelines have dependency confusion or typosquatting risks?
551. ⚠️ Are any of our container registries accessible without authentication?

### Multi-cloud combined posture
552. ⚠️ Give me a combined risk score across AWS, Azure, and GCP environments.
553. ⚠️ Which cloud provider has the most critical unpatched vulnerabilities?
554. ⚠️ Show me cross-cloud IAM misconfigurations — federated roles, excessive permissions.
555. ⚠️ Compare our security posture across AWS, Azure, and GCP side by side.
556. ⚠️ What's our total cloud attack surface across all three providers?
557. ⚠️ Are there any cross-cloud network paths that bypass our security controls?
558. ⚠️ Show me multi-cloud compliance status for SOC 2 controls.
559. ⚠️ Which cloud accounts across all providers have no vulnerability scanning enabled?
560. ⚠️ Give me an executive summary of our multi-cloud security posture with top risks.

---

## Coverage Summary

| Category | Total | ✅ Full | ⚠️ Partial | ❌ Gap | Coverage % |
|----------|-------|---------|-----------|--------|------------|
| Investigation Chaining | 10 | 7 | 3 | 0 | 85% |
| Vulnerability Management | 90 | 58 | 14 | 18 | 72% |
| Patch Management | 50 | 7 | 5 | 38 | 19% |
| TruRisk Eliminate | 30 | 13 | 2 | 15 | 47% |
| Cloud Security | 70 | 14 | 9 | 47 | 26% |
| Container Security | 40 | 6 | 6 | 28 | 22% |
| Web Application Security | 50 | 8 | 12 | 30 | 28% |
| Endpoint / EDR + FIM | 35 | 15 | 13 | 7 | 61% |
| Certificates / CertView | 30 | 13 | 10 | 7 | 60% |
| Asset Management | 40 | 14 | 13 | 13 | 51% |
| Compliance | 45 | 7 | 4 | 34 | 20% |
| Scanner / Infrastructure | 20 | 9 | 4 | 7 | 55% |
| Growth Engine | 5 | 4 | 1 | 0 | 90% |
| 2026 Threat Landscape | 55 | 0 | 48 | 7 | 44% |
| **Total** | **570** | **170** | **146** | **254** | **43%** |

> **Updated v2.17:** 570 questions across 14 categories. Coverage at 43% (170 ✅) with 29 active tools. 2026 Threat Landscape refreshed: replaced tenant-specific framework sections (NIST CSF 2.0, PCI-DSS v4.0, DORA) with zero-day response workflows, TruRisk prioritization, and supply chain / container provenance questions. Section coverage improved from 25% → 44%. Strongest categories: Investigation (85%), Growth Engine (90%), VM (72%), EDR+FIM (61%), Certificates (60%). See `docs/gaps.md` for detailed gap analysis.

---

<!-- conversations: BEGIN (parsed by eval/conversations.py — do not remove this marker) -->

```yaml
conversations:

  # ── Context Carryover (5 scenarios) ──────────────────────────────

  - name: "log4shell-investigation"
    category: "context-carryover"
    turns:
      - user: "Investigate Log4Shell in our environment"
        expect: "mentions CVE-2021-44228, affected assets count, severity"
      - user: "Which of those affected assets are running in production?"
        expect: "filters or references previous Log4Shell results, mentions production assets"
        context_check: "uses asset count or names from turn 1"
      - user: "What's the patch status for those production assets?"
        expect: "patch availability or status for the production assets identified"
        context_check: "references production assets from turn 2"
      - user: "Generate a remediation plan for the top 5 by TruRisk"
        expect: "remediation plan mentioning TruRisk scores, prioritized assets from prior context"
        context_check: "uses TruRisk scores or asset info from prior turns"

  - name: "critical-vuln-drilldown"
    category: "context-carryover"
    turns:
      - user: "What are our most critical vulnerabilities right now?"
        expect: "lists critical/high severity vulns with counts or details"
      - user: "Tell me more about the top one"
        expect: "detailed information about the highest severity vuln from turn 1"
        context_check: "references the specific vuln identified as top in turn 1"
      - user: "How many assets does it affect?"
        expect: "asset count for the specific vulnerability discussed"
        context_check: "refers to the same vulnerability from turn 2"
      - user: "What's the fix?"
        expect: "patch or remediation info for that vulnerability"
        context_check: "provides fix for the vulnerability from prior turns"

  - name: "cloud-posture-investigation"
    category: "context-carryover"
    turns:
      - user: "Give me an overview of our cloud security posture"
        expect: "cloud security summary across providers, control pass/fail counts"
      - user: "Which provider has the most failures?"
        expect: "identifies the worst cloud provider from the overview"
        context_check: "uses data from the cloud overview in turn 1"
      - user: "What are the critical failures there?"
        expect: "lists critical failing controls for the identified provider"
        context_check: "drills into the provider identified in turn 2"
      - user: "How do we fix those?"
        expect: "remediation steps for the critical failures"
        context_check: "references the specific failures from turn 3"

  - name: "patch-status-workflow"
    category: "context-carryover"
    turns:
      - user: "What's our overall patching status?"
        expect: "patching metrics, coverage percentage, or open patch counts"
      - user: "Which systems are furthest behind?"
        expect: "identifies systems with most missing patches"
        context_check: "uses patching data from turn 1"
      - user: "What patches are they missing?"
        expect: "specific missing patches for the behind systems"
        context_check: "references the systems identified in turn 2"

  - name: "asset-investigation-flow"
    category: "context-carryover"
    turns:
      - user: "Show me our riskiest assets"
        expect: "list of high-risk assets with risk scores"
      - user: "What's running on the top one?"
        expect: "software, OS, or services on the riskiest asset"
        context_check: "references the specific asset from turn 1"
      - user: "Does it have any EOL software?"
        expect: "end-of-life software check for that asset"
        context_check: "checks the same asset from turn 2"
      - user: "What's the full vulnerability list for it?"
        expect: "vulnerability list for the asset under investigation"
        context_check: "still referring to the same asset"

  # ── Pronoun / Reference Resolution (5 scenarios) ────────────────

  - name: "pronoun-top-vulns"
    category: "reference-resolution"
    turns:
      - user: "What are our top 10 vulnerabilities by TruRisk?"
        expect: "list of top vulnerabilities ranked by TruRisk score"
      - user: "Which of those have known exploits?"
        expect: "filters the top 10 to those with exploit availability"
        context_check: "filters from the list in turn 1, not a new search"
      - user: "Now just the Windows ones"
        expect: "further filters to Windows-only vulnerabilities"
        context_check: "applies OS filter to the already-filtered list"
      - user: "What's the patch info for those?"
        expect: "patch availability for the filtered Windows vulns"
        context_check: "references the Windows-filtered vulns from turn 3"

  - name: "pronoun-asset-group"
    category: "reference-resolution"
    turns:
      - user: "Which asset group has the highest risk?"
        expect: "identifies the riskiest asset group"
      - user: "Drill into that one"
        expect: "details about the identified asset group"
        context_check: "references the asset group from turn 1"
      - user: "What vulns are driving the risk there?"
        expect: "top vulnerabilities in that asset group"
        context_check: "scoped to the same asset group"
      - user: "How would we remediate those?"
        expect: "remediation guidance for the group's top vulns"
        context_check: "references the vulns from turn 3"

  - name: "pronoun-detection-investigate"
    category: "reference-resolution"
    turns:
      - user: "What detections fired this week?"
        expect: "recent detection or vulnerability activity"
      - user: "Tell me about the most severe one"
        expect: "details on the highest severity detection"
        context_check: "references specific detection from turn 1"
      - user: "Which assets does it affect?"
        expect: "assets affected by that detection"
        context_check: "uses the detection from turn 2"

  - name: "pronoun-dashboard-worst"
    category: "reference-resolution"
    turns:
      - user: "Give me a vulnerability dashboard summary"
        expect: "summary with severity counts, risk scores, or key metrics"
      - user: "What's the worst category?"
        expect: "identifies the weakest area from the dashboard"
        context_check: "references dashboard data from turn 1"
      - user: "Show me the details on that"
        expect: "drill-down into the worst category"
        context_check: "references the category from turn 2"
      - user: "What should we prioritize first?"
        expect: "prioritized action items for that category"
        context_check: "scoped to the same category"

  - name: "pronoun-severity-filter"
    category: "reference-resolution"
    turns:
      - user: "Show me all critical severity vulnerabilities"
        expect: "list or count of critical vulnerabilities"
      - user: "How many of those are actively exploited?"
        expect: "filters criticals to actively exploited subset"
        context_check: "filters from critical vulns in turn 1"
      - user: "Prioritize them for me"
        expect: "prioritized list of the actively exploited criticals"
        context_check: "prioritizes the filtered set from turn 2"
      - user: "Give me a brief I can send to management"
        expect: "executive summary of the prioritized critical vulns"
        context_check: "summarizes the context from prior turns"

  # ── Investigation Pivot (5 scenarios) ───────────────────────────

  - name: "pivot-cloud-to-iam"
    category: "investigation-pivot"
    turns:
      - user: "What's our cloud security posture?"
        expect: "cloud posture overview across providers"
      - user: "Focus on AWS"
        expect: "AWS-specific security findings or controls"
        context_check: "narrows to AWS from the overview"
      - user: "What IAM issues do we have?"
        expect: "IAM-related findings or misconfigurations in AWS"
        context_check: "further narrows to IAM within AWS"
      - user: "How does Azure compare?"
        expect: "Azure security posture, possibly compared to AWS"
        context_check: "pivots to Azure while referencing AWS context"

  - name: "pivot-vuln-to-patch"
    category: "investigation-pivot"
    turns:
      - user: "Investigate CVE-2024-3400"
        expect: "details about CVE-2024-3400, affected systems"
      - user: "What assets are affected?"
        expect: "list of affected assets"
        context_check: "assets for the specific CVE"
      - user: "What's the patch status?"
        expect: "patch availability and deployment status"
        context_check: "patch info for the CVE's affected assets"
      - user: "How long has this been open?"
        expect: "timeline or age of the vulnerability exposure"
        context_check: "references the same CVE context"

  - name: "pivot-edr-to-vulns"
    category: "investigation-pivot"
    turns:
      - user: "Any EDR detections recently?"
        expect: "recent EDR detection activity or alerts"
      - user: "What do we know about the host that triggered it?"
        expect: "asset details for the host with the detection"
        context_check: "references the host from EDR detection"
      - user: "Does that host have any unpatched vulns?"
        expect: "vulnerability status for the identified host"
        context_check: "checks vulns on the same host"

  - name: "pivot-was-to-remediation"
    category: "investigation-pivot"
    turns:
      - user: "How are our web applications doing security-wise?"
        expect: "web application security summary"
      - user: "Which app has the most findings?"
        expect: "identifies the worst web application"
        context_check: "references WAS data from turn 1"
      - user: "What kind of vulnerabilities does it have?"
        expect: "vulnerability types for that application (XSS, SQLi, etc.)"
        context_check: "details for the specific app from turn 2"
      - user: "What should the dev team fix first?"
        expect: "prioritized remediation for the app's vulns"
        context_check: "scoped to the same application"

  - name: "pivot-compliance-to-remediation"
    category: "investigation-pivot"
    turns:
      - user: "Where do we stand on compliance?"
        expect: "compliance posture summary, framework pass/fail rates"
      - user: "What controls are we failing?"
        expect: "list of failing compliance controls"
        context_check: "references compliance data from turn 1"
      - user: "What's the remediation plan for those?"
        expect: "remediation steps for failing controls"
        context_check: "addresses the specific failing controls from turn 2"
      - user: "Which ones can we fix fastest?"
        expect: "quick-win controls prioritized by effort"
        context_check: "prioritizes from the remediation plan"

  # ── Natural Analyst Workflow (5 scenarios) ──────────────────────

  - name: "workflow-morning-standup"
    category: "natural-workflow"
    turns:
      - user: "Morning standup — what's new since yesterday?"
        expect: "recent security changes, new detections, or vuln updates"
      - user: "Anything related to ransomware?"
        expect: "ransomware-associated vulnerabilities or threat intel"
        context_check: "filters recent activity to ransomware context"
      - user: "How many assets are exposed?"
        expect: "asset count for ransomware exposure"
        context_check: "references the ransomware vulns from turn 2"
      - user: "Draft a quick CISO brief on this"
        expect: "executive-style brief covering the ransomware situation"
        context_check: "summarizes all prior context into a brief"

  - name: "workflow-weekly-review"
    category: "natural-workflow"
    turns:
      - user: "Weekly security review — give me the highlights"
        expect: "weekly summary of security posture changes"
      - user: "What are the worst open issues?"
        expect: "top unresolved security issues"
        context_check: "references the weekly review context"
      - user: "Create a fix plan for those"
        expect: "remediation plan for the worst issues"
        context_check: "plan for the issues identified in turn 2"
      - user: "Format that as a ticket I can assign"
        expect: "structured ticket format with assignable action items"
        context_check: "formats the fix plan from turn 3"

  - name: "workflow-incident-response"
    category: "natural-workflow"
    turns:
      - user: "We might have a security incident — what's our current exposure to actively exploited vulns?"
        expect: "actively exploited vulnerabilities in the environment"
      - user: "What's the scope — how many systems?"
        expect: "system count and scope for actively exploited vulns"
        context_check: "scopes the exploited vulns from turn 1"
      - user: "What's the remediation path?"
        expect: "remediation steps for the exposed systems"
        context_check: "remediation for the scoped systems"
      - user: "Give me a timeline estimate"
        expect: "estimated remediation timeline"
        context_check: "timeline based on the remediation plan"

  - name: "workflow-executive-prep"
    category: "natural-workflow"
    turns:
      - user: "I'm prepping for a board meeting — what are our key security metrics?"
        expect: "high-level security KPIs and metrics"
      - user: "What's the risk story — are we getting better or worse?"
        expect: "trend analysis of security posture"
        context_check: "builds on the metrics from turn 1"
      - user: "What's our biggest risk right now?"
        expect: "top risk area with supporting data"
        context_check: "references the trend/metrics context"
      - user: "What's our recommendation to the board?"
        expect: "strategic recommendation with supporting evidence"
        context_check: "synthesizes all prior context"

  - name: "workflow-audit-prep"
    category: "natural-workflow"
    turns:
      - user: "We have a compliance audit next week — give me the current state"
        expect: "compliance posture summary across frameworks"
      - user: "Which controls are we failing?"
        expect: "list of failing controls"
        context_check: "references compliance data from turn 1"
      - user: "Where are the gaps?"
        expect: "gap analysis for compliance coverage"
        context_check: "builds on failing controls from turn 2"
      - user: "What evidence can we show for the passing controls?"
        expect: "evidence or documentation for passing controls"
        context_check: "references the passing controls from the posture overview"
```

<!-- conversations: END -->
