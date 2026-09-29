import json, urllib.request, urllib.parse, time, io, sys, calendar, collections
UA={"User-Agent":"lit-scan/0.1 (research planning; mailto:research-planning@example.org)"}
def get(url):
    for i in range(6):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=120) as r:
                return json.loads(r.read().decode("utf-8"))
        except Exception as e:
            print("  err", repr(e)[:120], flush=True); time.sleep(10+10*i)
    return None
months=[]
y,m=2023,11
while (y,m)<=(2026,9):
    months.append((y,m)); m+=1
    if m==13: y,m=y+1,1
out=io.open("nvd_v4_records.jsonl","w",encoding="utf-8")
stats=[]
for (y,m) in months:
    last=calendar.monthrange(y,m)[1]
    if (y,m)==(2026,9): last=24
    start=f"{y}-{m:02d}-01T00:00:00.000"; end=f"{y}-{m:02d}-{last:02d}T23:59:59.999"
    idx=0; tot=None; n=n31=n40=nboth=0; src40=collections.Counter()
    while True:
        q={"pubStartDate":start,"pubEndDate":end,"resultsPerPage":"2000","startIndex":str(idx)}
        d=get("https://services.nvd.nist.gov/rest/json/cves/2.0?"+urllib.parse.urlencode(q))
        time.sleep(6.5)
        if d is None: print("FAILED", y, m, idx, flush=True); break
        tot=d.get("totalResults",0)
        for v in d.get("vulnerabilities",[]):
            c=v["cve"]; mt=c.get("metrics",{})
            v31=[(x.get("source"),x.get("type"),x["cvssData"]["vectorString"]) for x in mt.get("cvssMetricV31",[])]
            v40=[(x.get("source"),x.get("type"),x["cvssData"]["vectorString"]) for x in mt.get("cvssMetricV40",[])]
            n+=1; n31+=bool(v31); n40+=bool(v40); nboth+=bool(v31 and v40)
            for s,_,_ in v40: src40[s]+=1
            if v40:
                desc=next((x["value"] for x in c.get("descriptions",[]) if x.get("lang")=="en"),"")
                out.write(json.dumps({"id":c["id"],"published":c.get("published"),"status":c.get("vulnStatus"),"v31":v31,"v40":v40,"desc_len":len(desc)},ensure_ascii=False)+"\n")
        idx+=2000
        if idx>=tot: break
    rec={"month":f"{y}-{m:02d}","total":tot,"seen":n,"with_v31":n31,"with_v40":n40,"with_both":nboth,"top_v40_sources":src40.most_common(8)}
    stats.append(rec); print(json.dumps(rec,ensure_ascii=False), flush=True)
    out.flush()
json.dump(stats, io.open("nvd_v4_stats.json","w",encoding="utf-8"), ensure_ascii=False, indent=1)
print("DONE", flush=True)
