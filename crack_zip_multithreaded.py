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
        
        # 设置线程数，默认使用CPU核心数
        self.threads = threads if threads else multiprocessing.cpu_count()
        
        # 注册信号处理
        signal.signal(signal.SIGINT, self.handle_interrupt)
        
        # 缓存已尝试的密码结果
        self.password_results = {}
        self.results_lock = threading.Lock()
        
        # 检查是否有检查点
        self.load_checkpoint()
        
    def handle_interrupt(self, sig, frame):
        """处理Ctrl+C中断"""
        print("\n\n中断检测到! 正在保存进度...")
        self.save_checkpoint()
        self.running = False
    
    def save_checkpoint(self):
        """保存当前进度到检查点文件"""
        checkpoint = {
            "count": self.count,
            "current_length": self.current_length,
            "current_position": self.current_position,
            "elapsed_time": time.time() - self.start_time + self.elapsed_time,
            "error_counts": self.error_counts
        }
        
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
                self.current_length = checkpoint.get("current_length", self.min_digits)
                self.current_position = checkpoint.get("current_position", 0)
                self.elapsed_time = checkpoint.get("elapsed_time", 0)
                self.error_counts = checkpoint.get("error_counts", {})
                
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
    
    def extract_file_from_zip(self, zip_file, password_str, temp_dir):
        """从ZIP文件中提取内容并检查是否成功"""
        try:
            # 尝试选择一个较小的文件来解压，以加快速度
            namelist = zip_file.namelist()
            
            # 如果文件列表为空，无法选择文件进行解压测试
            if not namelist:
                # 尝试解压所有文件
                zip_file.extractall(path=temp_dir, pwd=password_str.encode('utf-8'))
                return True
                
            # 选择第一个文件进行解压测试，通常是较小的文件
            smallest_file = namelist[0]
            
            # 找出最小的非目录文件
            for name in namelist:
                try:
                    info = zip_file.getinfo(name)
                    # 跳过目录
                    if name.endswith('/') or info.file_size == 0:
                        continue
                    # 找出文件大小最小的文件
                    if info.file_size < zip_file.getinfo(smallest_file).file_size or smallest_file.endswith('/'):
                        smallest_file = name
                except:
                    continue

            # 尝试仅解压这个小文件进行测试
            zip_file.extract(smallest_file, path=temp_dir, pwd=password_str.encode('utf-8'))
            
            # 检查是否成功解压
            if os.listdir(temp_dir):
                return True
            return False
        except (RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile):
            # 密码不正确
            return False
        except Exception as e:
            # 其他错误，但可能是因为文件被部分解压了，也可能是密码正确
            error_type = str(e)
            if "Error -3 while decompressing data" in error_type:
                # 这种错误通常在密码正确但文件损坏时出现
                # 尝试检查是否有任何文件被解压出来
                if os.listdir(temp_dir):
                    # 如果有文件解压出来，虽然有错误，但可能密码是正确的
                    # 再次尝试完整解压以确认
                    try:
                        # 清空临时目录
                        for item in os.listdir(temp_dir):
                            item_path = os.path.join(temp_dir, item)
                            if os.path.isfile(item_path):
                                os.unlink(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        
                        # 再次尝试解压所有文件
                        zip_file.extractall(path=temp_dir, pwd=password_str.encode('utf-8'))
                        if os.listdir(temp_dir):
                            return True
                    except:
                        pass
            
            with self.error_lock:
                if error_type in self.error_counts:
                    self.error_counts[error_type] += 1
                else:
                    self.error_counts[error_type] = 1
                    print(f"尝试密码时发生新类型错误: {error_type}")
            return False
        
    def worker(self, password_queue, zip_file):
        """工作线程函数"""
        # 创建临时目录用于尝试解压
        temp_dir = tempfile.mkdtemp()
        try:
            while self.running and not self.password_found:
                try:
                    # 非阻塞方式获取密码，如果队列为空就退出
                    try:
                        password_batch = password_queue.get(block=False)
                    except queue.Empty:
                        break
                    
                    for password_str in password_batch:
                        if not self.running or self.password_found:
                            break
                            
                        # 检查是否已经尝试过这个密码
                        with self.results_lock:
                            if password_str in self.password_results:
                                # 如果已经尝试过，跳过
                                continue
                            
                        with self.count_lock:
                            self.count += 1
                            current_count = self.count
                            
                            # 定期保存检查点，每10000个密码
                            if current_count % 10000 == 0:
                                self.current_position += 10000  # 更新位置
                                self.save_checkpoint()
                        
                        # 清空临时目录
                        for item in os.listdir(temp_dir):
                            item_path = os.path.join(temp_dir, item)
                            if os.path.isfile(item_path):
                                os.unlink(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        
                        # 尝试解压
                        success = self.extract_file_from_zip(zip_file, password_str, temp_dir)
                        
                        # 记录结果
                        with self.results_lock:
                            self.password_results[password_str] = success
                        
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
                            
                            break
                    
                    # 标记此批次已处理完毕
                    password_queue.task_done()
                    
                except Exception as e:
                    print(f"工作线程发生错误: {e}")
                    break
        finally:
            # 清理临时目录
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    def generate_passwords(self, digit_length, start_pos=0, batch_size=100):
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
                
                self.current_length = digit_length  # 更新当前位数
                start_pos = self.current_position if digit_length == self.current_length else 0
                self.current_position = start_pos  # 重置位置计数器，如果是新的位数
                
                print(f"\n尝试 {digit_length} 位数字密码...")
                if start_pos > 0:
                    print(f"从位置 {start_pos} 继续...")
                
                # 计算该位数的所有可能密码数量
                total_for_length = 10 ** digit_length
                remaining = total_for_length - start_pos
                print(f"共有 {total_for_length} 种可能组合，剩余 {remaining} 种未尝试")
                
                # 生成密码批次并放入队列
                for password_batch in self.generate_passwords(digit_length, start_pos, batch_size=100):
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
                password_queue.join()
                
                if self.password_found:
                    # 密码找到了，删除检查点文件
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
                
                # 当前位数处理完毕，更新检查点
                self.current_position = 0  # 重置位置
                self.current_length = digit_length + 1  # 准备下一个位数
                self.save_checkpoint()
            
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
                    percent_current = min(100, (self.current_position + count_diff) / total_for_current * 100)
                    
                    # 估计剩余时间
                    total_combinations = sum(10**d for d in range(self.current_length, self.max_digits + 1))
                    completed_combinations = sum(10**d for d in range(self.min_digits, self.current_length)) + self.current_position + count_diff
                    remaining_combinations = total_combinations - completed_combinations
                    
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