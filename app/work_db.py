from datetime import datetime
import requests

START_TIMESTAMP_DATE = 1262304000
COEF_SPEED_CONVERTING = 0.01

class Packet_data:
    tid = oid = evid = tm = lat = long = spd = dir = alt = vld = bb = src = 0
    imei = coords = sensors = ""
    llsd = []

    # Статические переменные.
    is_main = db_connection = cursor = in_local = None
    loc_db_connection = loc_cursor = None

    def update_auth(self, tid, imei):
        self.tid = tid
        self.imei = imei

    def set_oid(self, oid):
        self.oid = oid

    def set_evid(self, evid):
        self.evid = evid

    # def set_tm(self, tm):
    #     self.tm = tm

    def update_pos_data(self, ntm, lat, long, lohs, lahs, bb, vld, spd, dir, src, alt):
        self.lat = round(lat * 90 / 4294967295, 6)
        self.long = round(long * 180 / 4294967295, 6)

        if lahs and lohs:
            self.coords = "SE"

        elif lahs:
            self.coords = "SW"

        elif lohs:
            self.coords = "NE"

        else:
            self.coords = "NW"

        self.bb = bb
        self.vld = vld
        self.spd = spd * COEF_SPEED_CONVERTING
        self.dir = dir
        self.src = src
        self.alt = alt
        self.tm = ntm + START_TIMESTAMP_DATE
        
    def update_llsd(self, llsd):
        self.llsd.append(llsd)

    def reset_llsd(self):
        self.llsd = []

    def gts_data_save(self):
        # Если колво значений меньше 4, то заполняем -1.
        while len(self.llsd) < 4:
            self.llsd.append(0)

        insert_data = [
            self.imei,
            self.tid,
            self.oid,
            self.evid,
            self.tm,
            self.lat,
            self.long,
            self.coords,
            self.spd,
            self.dir,
            self.alt,
            self.vld,
            self.bb,
            self.src,
            self.llsd[0],
            self.llsd[1],
            self.llsd[2],
            self.llsd[3],
            self.sensors,
        ]
        
        data = {
            "id": self.imei,
            "old_id":  self.imei,
            "lat": self.lat,
            "lon": self.long,
            "speed": self.spd,
            "alt": self.alt,
            "timestamp": self.tm,
            "bearing": self.dir
        }
        request = requests.get("http://192.168.101.31:1065/", params=data)
        print(request.url)
        print(request.text)

        print(f"{self.lat=} {self.long=} speed={self.spd} time={self.tm}")

        print(f"{self.imei=} {self.tid=} {self.oid=} {self.evid=} {self.tm=} {self.lat} {self.long} {self.coords=} {self.spd=} {self.dir=} {self.alt=} {self.vld=} {self.bb=} {self.src=} {self.llsd=} {self.sensors=}")
     