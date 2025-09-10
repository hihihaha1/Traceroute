import folium
import requests

def get_coordinates_by_ip(ip):
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,status,message")
        data = response.json()
        if data["status"] == "success":
            return data["lat"], data["lon"]
        else:
            print(f"Ошибка геолокации IP {ip}: {data['message']}")
            return None
    except Exception as e:
        print(f"Сбой при геолокации IP {ip}: {e}")
        return None

def create_map_from_ips(ip_list):
    coordinates = []
    for ip in ip_list:
        coords = get_coordinates_by_ip(ip)
        if coords:
            coordinates.append((ip, coords))

    if len(coordinates) < 2:
        print("Недостаточно координат для построения маршрута.")
        return

    avg_lat = sum(lat for _, (lat, lon) in coordinates) / len(coordinates)
    avg_lon = sum(lon for _, (lat, lon) in coordinates) / len(coordinates)
    mapa = folium.Map(location=[avg_lat, avg_lon], zoom_start=3)

    for ip, (lat, lon) in coordinates:
        folium.Marker(
            location=[lat, lon],
            popup=f"IP: {ip}",
            icon=folium.Icon(color="blue", icon="info-sign")
        ).add_to(mapa)

    route = [[lat, lon] for _, (lat, lon) in coordinates]
    folium.PolyLine(locations=route, color="red", weight=2.5).add_to(mapa)

    mapa.save("Traceroute_Map.html")
    print("Карта с маршрутом сохранена как Traceroute_Map.html")