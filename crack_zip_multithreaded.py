#!/usr/bin/env python
# -*- coding: utf-8 -*-

import zipfile
import itertools
import string
import time
import os
import sys
import json
import signal
import threading
import queue
import multiprocessing
import tempfile
import shutil
import re

class ZipCracker:
    def __init__(self, zip_file, min_digits=3, max_digits=5, threads=None):
        self.zip_file_path = zip_file
        self.min_digits = min_digits
        self.max_digits = max_digits
        self.count = 0
        self.start_time = time.time()
        self.checkpoint_file = f"{os.path.basename(zip_file)}_checkpoint.json"
        self.running = True
        self.password_found = False
        self.found_password = None
        self.count_lock = threading.Lock()
        self.error_counts = {}  # 用于统计错误类型
        self.error_lock = threading.Lock()
        self.current_length = min_digits  # 当前正在尝试的位数
        self.current_position = 0  # 当前位数已尝试到的位置
        self.elapsed_time = 0  # 之前已花费的时间
        self.position_base = 0  # 用于跟踪当前位数的起始计数
        
        # 设置线程数，默认使用CPU核心数
        self.threads = threads if threads else multiprocessing.cpu_count()
        
        # 注册信号处理
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        # 缓存最小文件信息（用于快速密码测试）
        self.test_file_info = None
        self.test_file_lock = threading.Lock()
        
        # 检查是否有检查点
        self.load_checkpoint()
        
    def handle_interrupt(self, sig, frame):
        """处理Ctrl+C中断"""
        print("\n\n中断检测到! 正在保存进度...")
        self.running = False
        self.save_checkpoint()
        print("进度已保存，程序即将退出...")
        # 强制退出程序
        sys.exit(0)
    
    def save_checkpoint(self):
        """保存当前进度到检查点文件"""
        # 尝试获取锁，如果获取不到就使用当前已知的值
        # 这样可以避免在信号处理中死锁
        lock_acquired = self.count_lock.acquire(blocking=False)
        try:
            # 计算当前位数的实际位置
            actual_position = self.count - self.position_base
            checkpoint = {
                "count": self.count,
                "current_length": self.current_length,
                "current_position": actual_position,
                "elapsed_time": time.time() - self.start_time + self.elapsed_time,
                "error_counts": self.error_counts
            }
        finally:
            if lock_acquired:
                self.count_lock.release()
        
        try:
            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(checkpoint, f)
            print(f"进度已保存到 {self.checkpoint_file}，使用相同命令可以从此处继续。")
        except Exception as e:
            print(f"保存检查点失败: {e}")
    
    def load_checkpoint(self):
        """加载检查点继续破解"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                    checkpoint = json.load(f)
                
                self.count = checkpoint.get("count", 0)
                loaded_length = checkpoint.get("current_length", self.min_digits)
                self.current_position = checkpoint.get("current_position", 0)
                self.elapsed_time = checkpoint.get("elapsed_time", 0)
                self.error_counts = checkpoint.get("error_counts", {})
                
                # 验证 current_length 是否在有效范围内
                if loaded_length < self.min_digits or loaded_length > self.max_digits:
                    print(f"警告: 检查点中的位数 {loaded_length} 超出范围 {self.min_digits}-{self.max_digits}")
                    print("将从头开始破解")
                    self.count = 0
                    self.current_length = self.min_digits
                    self.current_position = 0
                    self.elapsed_time = 0
                    return False
                
                self.current_length = loaded_length
                
                # 计算之前位数的密码总数，用于设置 position_base
                self.position_base = sum(10**d for d in range(self.min_digits, self.current_length))
                
                print(f"从上次中断处继续: 已尝试 {self.count} 个密码")
                print(f"当前位数: {self.current_length}, 位置: {self.current_position}")
                print(f"已用时: {self.elapsed_time:.2f} 秒")
                
                # 调整开始时间，让进度显示正确
                self.start_time = time.time() - self.elapsed_time
                
                return True
            except Exception as e:
                print(f"加载检查点失败: {e}")
                print("将从头开始破解")
                return False
        return False
    
    def get_test_file_info(self, zip_file):
        """获取用于测试的最小文件信息（缓存）"""
        if self.test_file_info is None:
            with self.test_file_lock:
                # 双重检查锁定
                if self.test_file_info is None:
                    namelist = zip_file.namelist()
                    if not namelist:
                        self.test_file_info = None
                        return None
                    
                    # 找出最小的非目录文件
                    smallest_file = None
                    smallest_size = float('inf')
                    
                    for name in namelist:
                        try:
                            info = zip_file.getinfo(name)
                            # 跳过目录和空文件
                            if name.endswith('/') or info.file_size == 0:
                                continue
                            # 找出文件大小最小的文件
                            if info.file_size < smallest_size:
                                smallest_file = name
                                smallest_size = info.file_size
                        except:
                            continue
                    
                    self.test_file_info = smallest_file
        
        return self.test_file_info
    
    def test_password(self, zip_file, password_str):
        """快速测试密码是否正确（不实际解压到磁盘）"""
        try:
            # 获取测试文件
            test_file = self.get_test_file_info(zip_file)
            
            if test_file is None:
                # 如果没有合适的测试文件，尝试读取第一个文件
                namelist = zip_file.namelist()
                if not namelist:
                    return False
                test_file = namelist[0]
            
            # 尝试读取文件内容（只读取少量字节）
            # 这比实际解压到磁盘快得多
            with zip_file.open(test_file, pwd=password_str.encode('utf-8')) as f:
                # 只读取前1024字节来验证密码
                f.read(1024)
            
            return True
            
        except RuntimeError as e:
            # 密码错误会抛出 RuntimeError
            if "Bad password" in str(e) or "password" in str(e).lower():
                return False
            # 其他 RuntimeError 可能是文件问题
            return False
        except (zipfile.BadZipFile, zipfile.LargeZipFile):
            # ZIP文件问题
            return False
        except Exception as e:
            # 其他异常
            error_type = str(e)
            # 某些情况下即使密码正确也可能出错，但至少通过了密码验证
            if "Bad password" not in error_type and "password" not in error_type.lower():
                # 可能密码是正确的，只是文件有问题
                # 为了安全起见，再次验证
                try:
                    # 尝试获取文件信息
                    zip_file.getinfo(test_file)
                    return True
                except:
                    pass
            
            return False
        
    def worker(self, password_queue, zip_file):
        """工作线程函数"""
        try:
            while self.running and not self.password_found:
                password_batch = None
                try:
                    # 非阻塞方式获取密码，如果队列为空就退出
                    try:
                        password_batch = password_queue.get(block=False)
                    except queue.Empty:
                        break
                    
                    for password_str in password_batch:
                        if not self.running or self.password_found:
                            # 标记任务完成后再退出
                            password_queue.task_done()
                            return
                            
                        with self.count_lock:
                            self.count += 1
                            current_count = self.count
                            
                            # 定期保存检查点，每10000个密码
                            if current_count % 10000 == 0:
                                self.save_checkpoint()
                        
                        # 快速测试密码（不写入磁盘，速度更快）
                        success = self.test_password(zip_file, password_str)
                        
                        if success:
                            # 密码找到了
                            self.password_found = True
                            self.found_password = password_str
                            
                            with self.count_lock:
                                elapsed = time.time() - self.start_time + self.elapsed_time
                                print(f"\n密码找到了! 密码是: {password_str}")
                                print(f"总共尝试了 {current_count} 个密码组合")
                                print(f"用时: {elapsed:.2f} 秒")
                            
                            # 删除检查点文件
                            if os.path.exists(self.checkpoint_file):
                                try:
                                    os.remove(self.checkpoint_file)
                                except:
                                    pass
                            
                            # 标记任务完成后再退出
                            password_queue.task_done()
                            return
                    
                    # 正常完成批次处理，标记任务完成
                    password_queue.task_done()
                    
                except Exception as e:
                    print(f"工作线程发生错误: {e}")
                    # 如果获取到了任务，确保标记为完成
                    if password_batch is not None:
                        try:
                            password_queue.task_done()
                        except:
                            pass
                    break
        finally:
            pass  # 不再需要清理临时目录
    
    def generate_passwords(self, digit_length, start_pos=0, batch_size=500):
        """生成指定位数的所有可能密码，按批次返回，支持从指定位置开始"""
        batch = []
        # 跳过到开始位置
        password_iterator = itertools.product(string.digits, repeat=digit_length)
        
        # 跳过已尝试的密码
        for _ in range(start_pos):
            try:
                next(password_iterator)
            except StopIteration:
                return  # 没有更多密码了
        
        # 生成剩余密码
        for password in password_iterator:
            password_str = ''.join(password)
            batch.append(password_str)
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
                
        if batch:  # 处理剩余的密码
            yield batch
    
    def crack(self):
        """开始多线程破解过程"""
        if not os.path.exists(self.zip_file_path):
            print(f"错误: 文件 {self.zip_file_path} 不存在!")
            return False
        
        try:
            zip_file = zipfile.ZipFile(self.zip_file_path)
        except zipfile.BadZipFile:
            print(f"错误: {self.zip_file_path} 不是有效的ZIP文件!")
            return False
        
        # 如果没有检查点，验证ZIP是否需要密码
        if self.count == 0:
            # 创建临时目录用于初始检查
            temp_dir = tempfile.mkdtemp()
            try:
                # 尝试无密码解压，检查是否需要密码
                try:
                    zip_file.extractall(path=temp_dir)
                    if os.listdir(temp_dir):
                        print("此ZIP文件不需要密码!")
                        return True
                    else:
                        print("解压后没有文件，可能需要密码。开始破解...")
                except RuntimeError as e:
                    if "password required" in str(e).lower() or "密码" in str(e).lower():
                        print("此ZIP文件需要密码，开始破解...")
                    else:
                        print(f"解压时出错: {e}")
                        print("尝试破解密码...")
                except Exception as e:
                    print(f"尝试解压时出错: {e}")
                    print("尝试破解密码...")
            finally:
                # 清理临时目录
                shutil.rmtree(temp_dir, ignore_errors=True)
        else:
            print("从检查点继续破解...")
        
        print(f"开始破解 {self.zip_file_path} 的密码...")
        print(f"尝试 {self.min_digits} 到 {self.max_digits} 位数字...")
        print(f"使用 {self.threads} 个线程并行处理")
        
        # 创建密码队列和线程池
        password_queue = queue.Queue()
        threads = []
        
        # 创建并启动显示进度的线程
        stop_progress = threading.Event()
        progress_thread = threading.Thread(target=self.show_progress, args=(stop_progress,))
        progress_thread.daemon = True
        progress_thread.start()
        
        try:
            # 尝试各种位数的密码，从检查点继续
            for digit_length in range(self.current_length, self.max_digits + 1):
                if self.password_found or not self.running:
                    break
                
                # 判断是否是恢复的位数还是新的位数
                is_resumed = (digit_length == self.current_length)
                start_pos = self.current_position if is_resumed else 0
                
                # 如果是新的位数，更新 position_base
                if not is_resumed:
                    self.current_length = digit_length
                    self.position_base = sum(10**d for d in range(self.min_digits, digit_length))
                    self.current_position = 0
                
                print(f"\n尝试 {digit_length} 位数字密码...")
                if start_pos > 0:
                    print(f"从位置 {start_pos} 继续...")
                
                # 计算该位数的所有可能密码数量
                total_for_length = 10 ** digit_length
                remaining = total_for_length - start_pos
                print(f"共有 {total_for_length} 种可能组合，剩余 {remaining} 种未尝试")
                
                # 生成密码批次并放入队列
                for password_batch in self.generate_passwords(digit_length, start_pos, batch_size=500):
                    password_queue.put(password_batch)
                    
                    if self.password_found:
                        break
                
                # 创建工作线程
                threads = []
                for _ in range(self.threads):
                    t = threading.Thread(target=self.worker, args=(password_queue, zip_file))
                    t.daemon = True
                    t.start()
                    threads.append(t)
                
                # 等待所有密码尝试完毕或找到密码
                # 使用循环检查而不是无限期等待，以便能快速响应密码找到的情况
                while not self.password_found:
                    try:
                        # 使用超时的 join，这样可以定期检查 password_found 标志
                        if password_queue.empty() and all(not t.is_alive() for t in threads):
                            break
                        time.sleep(0.1)
                    except:
                        break
                
                # 如果找到密码，立即停止所有线程
                if self.password_found:
                    self.running = False
                    # 等待所有线程停止
                    for t in threads:
                        if t.is_alive():
                            t.join(timeout=1)
                    # 删除检查点文件
                    if os.path.exists(self.checkpoint_file):
                        try:
                            os.remove(self.checkpoint_file)
                        except:
                            pass
                    break
                
                # 确保所有线程已停止
                for t in threads:
                    if t.is_alive():
                        t.join(1)
            
            # 如果没有找到密码
            if not self.password_found and self.running:
                print("\n未能找到密码，已尝试所有可能的组合。")
                print(f"总共尝试了 {self.count} 个密码组合")
                total_time = time.time() - self.start_time + self.elapsed_time
                print(f"总用时: {total_time:.2f} 秒")
                
                # 显示错误统计
                if self.error_counts:
                    print("\n解压尝试中遇到的错误统计:")
                    for error_type, count in self.error_counts.items():
                        print(f"- {error_type}: {count}次")
                
                # 删除检查点文件，因为已经尝试完所有组合
                if os.path.exists(self.checkpoint_file):
                    try:
                        os.remove(self.checkpoint_file)
                    except:
                        pass
            
            # 停止进度显示线程
            stop_progress.set()
            progress_thread.join()
            
            return self.password_found
            
        except KeyboardInterrupt:
            print("\n操作被用户中断")
            self.running = False
            self.save_checkpoint()
            
            # 停止进度显示线程
            stop_progress.set()
            if progress_thread.is_alive():
                progress_thread.join()
                
            # 等待所有线程完成
            for t in threads:
                if t.is_alive():
                    t.join(1)
                    
            return False
        except Exception as e:
            print(f"破解过程发生错误: {e}")
            self.running = False
            self.save_checkpoint()
            
            # 停止进度显示线程
            stop_progress.set()
            if progress_thread.is_alive():
                progress_thread.join()
                
            return False
    
    def show_progress(self, stop_event):
        """显示进度的线程函数"""
        last_count = 0
        last_time = time.time()
        
        while not stop_event.is_set() and self.running:
            time.sleep(2)  # 每2秒更新一次进度
            
            with self.count_lock:
                current_count = self.count
                current_time = time.time()
                
                # 计算速度
                time_diff = current_time - last_time
                count_diff = current_count - last_count
                
                if time_diff > 0:
                    speed = count_diff / time_diff
                    elapsed = current_time - self.start_time + self.elapsed_time
                    
                    # 计算该位数的密码总数和已完成的百分比
                    total_for_current = 10 ** self.current_length
                    current_in_this_length = current_count - self.position_base
                    percent_current = min(100, current_in_this_length / total_for_current * 100)
                    
                    # 估计剩余时间
                    total_combinations = sum(10**d for d in range(self.min_digits, self.max_digits + 1))
                    remaining_combinations = total_combinations - current_count
                    
                    if speed > 0:
                        remaining_seconds = remaining_combinations / speed
                        if remaining_seconds < 60:
                            remaining = f"{remaining_seconds:.1f} 秒"
                        elif remaining_seconds < 3600:
                            remaining = f"{remaining_seconds/60:.1f} 分钟"
                        elif remaining_seconds < 86400:
                            remaining = f"{remaining_seconds/3600:.1f} 小时"
                        else:
                            remaining = f"{remaining_seconds/86400:.1f} 天"
                    else:
                        remaining = "未知"
                    
                    print(f"已尝试 {current_count} 个密码 | 当前位数进度: {percent_current:.1f}% | 速度: {speed:.1f} 密码/秒 | 用时: {elapsed:.1f}秒 | 预计剩余: {remaining}")
                    
                    # 更新上次计数和时间
                    last_count = current_count
                    last_time = current_time

if __name__ == "__main__":
    if len(sys.argv) > 1:
        zip_file = sys.argv[1]
    else:
        zip_file = "example.zip"
    
    min_digits = 3
    max_digits = 5
    threads = None  # 默认使用CPU核心数
    
    if len(sys.argv) > 2:
        min_digits = int(sys.argv[2])
    if len(sys.argv) > 3:
        max_digits = int(sys.argv[3])
    if len(sys.argv) > 4:
        threads = int(sys.argv[4])
    
    cracker = ZipCracker(zip_file, min_digits, max_digits, threads)
    cracker.crack() 