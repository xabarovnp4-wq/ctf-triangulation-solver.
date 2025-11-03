#!/usr/bin/env python3
from pwn import *
import math
import sys

def dist(a, b):
    return math.sqrt((a[0]-b[0])**2 + (a[1]-b[1])**2)

def solve_point(x1, y1, d1, x2, y2, d2, x3, y3, d3):
    """Надежное решение системы уравнений"""
    try:
        A12 = 2*x2 - 2*x1
        B12 = 2*y2 - 2*y1
        C12 = d1**2 - d2**2 - x1**2 + x2**2 - y1**2 + y2**2
        
        A13 = 2*x3 - 2*x1
        B13 = 2*y3 - 2*y1
        C13 = d1**2 - d3**2 - x1**2 + x3**2 - y1**2 + y3**2
        
        det = A12 * B13 - A13 * B12
        
        if abs(det) < 1e-12:
            return (x1+x2+x3)/3, (y1+y2+y3)/3
        
        x = (C12 * B13 - C13 * B12) / det
        y = (A12 * C13 - A13 * C12) / det
        
        error = abs(dist((x,y), (x1,y1)) - d1) + \
                abs(dist((x,y), (x2,y2)) - d2) + \
                abs(dist((x,y), (x3,y3)) - d3)
        
        if error > 1e-6:
            log.warning(f"Большая ошибка: {error:.2e}")
            return (x1+x2+x3)/3, (y1+y2+y3)/3
            
        return x, y
        
    except Exception as e:
        log.warning(f"Ошибка вычисления: {e}")
        return (x1+x2+x3)/3, (y1+y2+y3)/3

def parse_data(data):
    """Умный парсинг данных"""
    lines = data.split('\n')
    points = []
    distances = []
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        if any(x in line for x in ['a:', 'b:', 'c:', 'distance', 'x y>']):
            continue
            
        numbers = []
        for word in line.split():
            try:
                num = float(word)
                if 0 <= num <= 2:
                    numbers.append(num)
            except:
                pass
        
        if len(numbers) == 2:
            points.append((numbers[0], numbers[1]))
        elif len(numbers) == 1:
            distances.append(numbers[0])
    
    return points, distances

def main():
    log.info("Запуск CTF решателя...")
    
    try:
        r = remote('ppc.game.ctfcup.online', 1111, timeout=30)
        log.success("Подключение установлено!")
        
    except Exception as e:
        log.error(f"Ошибка подключения: {e}")
        return

    for round_num in range(120):
        try:
            log.info(f"Раунд {round_num + 1}/120")
            
            data = r.recvuntil(b'x y>', timeout=60).decode()
            points, distances = parse_data(data)
            
            if len(points) >= 3 and len(distances) >= 3:
                x1, y1 = points[0]
                x2, y2 = points[1]
                x3, y3 = points[2]
                d1, d2, d3 = distances[0], distances[1], distances[2]
                
                log.info(f"A: ({x1:.3f}, {y1:.3f}) d={d1:.3f}")
                log.info(f"B: ({x2:.3f}, {y2:.3f}) d={d2:.3f}")
                log.info(f"C: ({x3:.3f}, {y3:.3f}) d={d3:.3f}")
                
                x, y = solve_point(x1, y1, d1, x2, y2, d2, x3, y3, d3)
                answer = f"{x:.15f} {y:.15f}"
                r.sendline(answer.encode())
                log.success(f"Отправлено: ({x:.6f}, {y:.6f})")
                
            else:
                log.warning("Не удалось распарсить, отправляю центр масс")
                r.sendline(b"0.5 0.5")
                
        except EOFError:
            log.error("Сервер закрыл соединение")
            break
        except Exception as e:
            log.error(f"Ошибка в раунде {round_num + 1}: {e}")
            try:
                r.sendline(b"0.5 0.5")
            except:
                break

    try:
        log.info("Получаем флаг...")
        flag_data = r.recvall(timeout=10).decode()
        if flag_data:
            log.success(f"ФЛАГ: {flag_data}")
        else:
            log.info("Нет дополнительных данных")
    except Exception as e:
        log.error(f"Ошибка при получении флага: {e}")

    r.close()

if __name__ == "__main__":
    main()
