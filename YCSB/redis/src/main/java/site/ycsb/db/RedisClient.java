/**
 * Copyright (c) 2012 YCSB contributors. All rights reserved.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the License. You
 * may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * permissions and limitations under the License. See accompanying
 * LICENSE file.
 */

/**
 * Redis client binding for YCSB.
 *
 * All YCSB records are mapped to a Redis *hash field*.  For scanning
 * operations, all keys are saved (by an arbitrary hash) in a sorted set.
 */

package site.ycsb.db;

import redis.clients.jedis.Tuple;
import site.ycsb.ByteArrayByteIterator;
import site.ycsb.ByteIterator;
import site.ycsb.DB;
import site.ycsb.DBException;
import site.ycsb.Status;
import redis.clients.jedis.HostAndPort;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisCluster;
import redis.clients.jedis.JedisCommands;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.Protocol;
import site.ycsb.StringByteIterator;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.concurrent.atomic.AtomicInteger;

import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * YCSB binding for <a href="http://redis.io/">Redis</a>.
 *
 * 多线程共享一个 JedisPool（单机）或 JedisCluster（集群，自带连接池），
 * 每次操作通过 try-with-resources 从池中借用连接，避免每个线程独占长连接。
 *
 * See {@code redis/README.md} for details.
 */
public class RedisClient extends DB {

  public static final String HOST_PROPERTY = "redis.host";
  public static final String PORT_PROPERTY = "redis.port";
  public static final String PASSWORD_PROPERTY = "redis.password";
  public static final String CLUSTER_PROPERTY = "redis.cluster";
  public static final String COMMAND_PROPERTY = "redis.command_group";
  public static final String TIMEOUT_PROPERTY = "redis.timeout";
  public static final String DEBUG_PROPERTY = "redis.debug";
  public static final String RANGE_PROPERTY = "redis.range";

  // 连接池相关参数
  public static final String POOL_MAX_TOTAL_PROPERTY = "redis.pool.max_total";
  public static final String POOL_MAX_IDLE_PROPERTY = "redis.pool.max_idle";
  public static final String POOL_MIN_IDLE_PROPERTY = "redis.pool.min_idle";
  public static final String POOL_MAX_WAIT_MILLIS_PROPERTY = "redis.pool.max_wait_millis";
  public static final String POOL_TEST_ON_BORROW_PROPERTY = "redis.pool.test_on_borrow";

  public static final String FIELD_COUNT = "fieldcount";
  public static final String FIELD_LENGTH = "fieldlength";

  /** the default command group is "string", it can be {string, hash}. */
  public enum CommandType {
    COMMAND_STRING,
    COMMAND_HASH,
    COMMAND_LIST,
    COMMAND_SET,
    COMMAND_ZSET
  }

  private static final String STRING_COMMAND = "string";
  private static final String HASH_COMMAND = "hash";
  private static final String LIST_COMMAD = "list";
  private static final String SET_COMMAND = "set";
  private static final String ZSET_COMMAND = "zset";

  private static final String RETURN_OK = "OK";

  private static final Set<String> COMMAND_TABLE = new HashSet<String>() {
    {
      add(STRING_COMMAND);
      add(HASH_COMMAND);
      add(LIST_COMMAD);
      add(SET_COMMAND);
      add(ZSET_COMMAND);
    }
  };

  // ===== 共享的连接池（所有 YCSB 工作线程共用） =====
  private static final Object POOL_LOCK = new Object();
  private static volatile JedisPool jedisPool;
  private static volatile JedisCluster jedisCluster;
  /** Reference count, ensures the pool is closed only when the last cleanup finishes. */
  private static final AtomicInteger REF_COUNT = new AtomicInteger(0);

  private boolean clusterEnabled = false;
  private String commandGroup = STRING_COMMAND;
  private CommandType commandType = CommandType.COMMAND_STRING;
  private int fieldCount = 0;
  private int fieldLength = 0;
  private int timeout = 2000;
  private Boolean debugMode = false;
  private int[] range = null;

  private static CommandType convertToCommandType(String command) throws DBException {
    if (command.equals(STRING_COMMAND)) {
      return CommandType.COMMAND_STRING;
    } else if (command.equals(HASH_COMMAND)) {
      return CommandType.COMMAND_HASH;
    } else if (command.equals(LIST_COMMAD)) {
      return CommandType.COMMAND_LIST;
    } else if (command.equals(SET_COMMAND)) {
      return CommandType.COMMAND_SET;
    } else if (command.equals(ZSET_COMMAND)) {
      return CommandType.COMMAND_ZSET;
    } else {
      throw new DBException(String.format("command %s is invalid", command));
    }
  }

  @Override
  public void init() throws DBException {
    Properties props = getProperties();
    int port;

    String debugModeString = props.getProperty(DEBUG_PROPERTY);
    if (debugModeString != null) {
      debugMode = Boolean.parseBoolean(debugModeString);
    }

    String rangeString = props.getProperty(RANGE_PROPERTY);
    if (rangeString != null) {
      range = new int[2];
      String[] r = rangeString.split(",");
      assert r.length == 2;
      range[0] = Integer.parseInt(r[0]);
      range[1] = Integer.parseInt(r[1]);
    }

    String fieldCountString = props.getProperty(FIELD_COUNT);
    if (fieldCountString != null) {
      fieldCount = Integer.parseInt(fieldCountString);
    }

    String fieldLengthString = props.getProperty(FIELD_LENGTH);
    if (fieldLengthString != null) {
      fieldLength = Integer.parseInt(fieldLengthString);
    }

    String portString = props.getProperty(PORT_PROPERTY);
    if (portString != null) {
      port = Integer.parseInt(portString);
    } else {
      port = Protocol.DEFAULT_PORT;
    }
    String host = props.getProperty(HOST_PROPERTY);

    String timeoutString = props.getProperty(TIMEOUT_PROPERTY);
    if (timeoutString != null) {
      timeout = Integer.parseInt(timeoutString);
    }

    clusterEnabled = Boolean.parseBoolean(props.getProperty(CLUSTER_PROPERTY));

    commandGroup = props.getProperty(COMMAND_PROPERTY, STRING_COMMAND);
    if (commandGroup == null) {
      throw new DBException("the command group is illegal");
    }
    if (!COMMAND_TABLE.contains(commandGroup)) {
      System.out.println("the command group should be in " + COMMAND_TABLE);
      throw new DBException(String.format("the command group is invalid, commandGroup: %s", commandGroup));
    }
    commandType = convertToCommandType(commandGroup);

    // 仅由第一个进入的线程初始化共享连接池/集群客户端，其余线程直接复用
    if (jedisPool == null && jedisCluster == null) {
      synchronized (POOL_LOCK) {
        if (jedisPool == null && jedisCluster == null) {
          String password = props.getProperty(PASSWORD_PROPERTY);
          if (clusterEnabled) {
            Set<HostAndPort> jedisClusterNodes = new HashSet<>();
            jedisClusterNodes.add(new HostAndPort(host, port));
            JedisPoolConfig poolConfig = buildPoolConfig(props);
            int maxAttempts = 5;
            if (password != null) {
              jedisCluster = new JedisCluster(jedisClusterNodes, timeout, timeout,
                  maxAttempts, password, poolConfig);
            } else {
              jedisCluster = new JedisCluster(jedisClusterNodes, timeout, maxAttempts, poolConfig);
            }
          } else {
            JedisPoolConfig poolConfig = buildPoolConfig(props);
            jedisPool = new JedisPool(poolConfig, host, port, timeout, password);
          }
        }
      }
    }

    REF_COUNT.incrementAndGet();

    if (debugMode) {
      System.out.println(String.format("Properties: %s", props.toString()));
    }
  }

  private static JedisPoolConfig buildPoolConfig(Properties props) {
    JedisPoolConfig config = new JedisPoolConfig();
    String maxTotal = props.getProperty(POOL_MAX_TOTAL_PROPERTY);
    String maxIdle = props.getProperty(POOL_MAX_IDLE_PROPERTY);
    String minIdle = props.getProperty(POOL_MIN_IDLE_PROPERTY);
    String maxWait = props.getProperty(POOL_MAX_WAIT_MILLIS_PROPERTY);
    String testOnBorrow = props.getProperty(POOL_TEST_ON_BORROW_PROPERTY);

    // 从 YCSB 全局属性获取线程数，以此动态计算池默认值
    int threads = Integer.parseInt(props.getProperty("threadcount", "1"));

    // 默认值：max_total = threads + 16, max_idle = min_idle = threads
    config.setMaxTotal(maxTotal != null ? Integer.parseInt(maxTotal) : threads + 16);
    config.setMaxIdle(maxIdle != null ? Integer.parseInt(maxIdle) : threads);
    config.setMinIdle(minIdle != null ? Integer.parseInt(minIdle) : threads);
    config.setMaxWaitMillis(maxWait != null ? Long.parseLong(maxWait) : 5000L);
    // 压测场景默认关闭 testOnBorrow，避免每次借连接都发 PING 多一次 RTT
    config.setTestOnBorrow(testOnBorrow != null && Boolean.parseBoolean(testOnBorrow));
    config.setBlockWhenExhausted(true);
    return config;
  }

  @Override
  public void cleanup() throws DBException {
    // 最后一个线程退出时才真正关闭共享池
    if (REF_COUNT.decrementAndGet() == 0) {
      synchronized (POOL_LOCK) {
        try {
          if (jedisPool != null) {
            jedisPool.close();
            jedisPool = null;
          }
          if (jedisCluster != null) {
            jedisCluster.close();
            jedisCluster = null;
          }
        } catch (IOException e) {
          throw new DBException("Closing connection failed.", e);
        }
      }
    }
  }

  /**
   * Operation callback that holds the real logic based on {@link JedisCommands};
   * {@link #execute(JedisOp)} is responsible for borrowing/returning the connection.
   */
  private interface JedisOp<T> {
    T apply(JedisCommands commands);
  }

  /**
   * Borrow a connection from the shared pool to execute the operation and return it
   * automatically afterwards (in cluster mode JedisCluster has its own internal pool).
   */
  private <T> T execute(JedisOp<T> op) {
    if (clusterEnabled) {
      return op.apply(jedisCluster);
    }
    try (Jedis jedis = jedisPool.getResource()) {
      return op.apply(jedis);
    }
  }

  // XXX jedis.select(int index) to switch to `table`

  @Override
  public Status read(String table, String key, Set<String> fields,
                     Map<String, ByteIterator> result) {
    return execute(commands -> doRead(commands, key, fields));
  }

  private Status doRead(JedisCommands commands, String key, Set<String> fields) {
    switch (commandType) {
    case COMMAND_STRING:
      if (fields == null) {
        String fieldValue = commands.get(key);
        if (debugMode) {
          System.out.println(String.format("get key:%s fields:%s, vals:%s", key, fields, fieldValue));
        }
        if (fieldValue != null && !fieldValue.isEmpty()) {
          return Status.OK;
        }
        return Status.NOT_FOUND;
      }
      break;
    case COMMAND_HASH:
      if (fields == null) {
        Map<String, String> values = commands.hgetAll(key);
        if (debugMode) {
          System.out.println(String.format("hgetAll key:%s, vals:%s", key, values));
        }
        if (values != null && !values.isEmpty()) {
          return Status.OK;
        }
        return Status.NOT_FOUND;
      }
      break;
    case COMMAND_LIST:
      if (fields == null) {
        int startIdx = 0;
        int endIdx = -1;
        if (range != null) {
          startIdx = range[0];
          endIdx = range[1];
        }
        List<String> values = commands.lrange(key, startIdx, endIdx);
        if (debugMode) {
          System.out.println(String.format("lrange key:%s start:%d end:%d, vals:%s", key, startIdx, endIdx, values));
        }
        if (values != null && !values.isEmpty()) {
          return Status.OK;
        }
        return Status.NOT_FOUND;
      }
      break;
    case COMMAND_SET:
      if (fields == null) {
        Set<String> members = commands.smembers(key);
        if (debugMode) {
          System.out.println(String.format("smembers key:%s, vals:%s", key, members));
        }
        if (members != null && !members.isEmpty()) {
          return Status.OK;
        }
        return Status.NOT_FOUND;
      }
      break;
    case COMMAND_ZSET:
      if (fields == null) {
        int startIdx = 0;
        int endIdx = -1;
        if (range != null) {
          startIdx = range[0];
          endIdx = range[1];
        }
        Set<Tuple> members = commands.zrangeWithScores(key, startIdx, endIdx);
        if (debugMode) {
          System.out.println(String.format("zrangeWithScores key:%s start:%d end:%d, vals:%s",
              key, startIdx, endIdx, members));
        }
        if (members != null && !members.isEmpty()) {
          return Status.OK;
        }
        return Status.NOT_FOUND;
      }
      break;
    default:
    }
    return Status.ERROR;
  }

  @Override
  public Status insert(String table, String key,
                       Map<String, ByteIterator> values) {
    return execute(commands -> doInsert(commands, key, values));
  }

  private Status doInsert(JedisCommands commands, String key, Map<String, ByteIterator> values) {
    switch (commandType) {
    case COMMAND_STRING:
      if (fieldCount == 1) {
        assert values.size() == 1;
        Map.Entry<String, ByteIterator> field0 = values.entrySet().iterator().next();
        String field0Value = field0.getValue().toString();
        if (debugMode) {
          System.out.println(String.format("set key:%s val:%s", key, field0Value));
        }
        String stringRet = commands.set(key, field0Value);
        if (stringRet.equals(RETURN_OK)) {
          return Status.OK;
        }
      }
      break;
    case COMMAND_HASH:
      Map<String, String> fieldValues = StringByteIterator.getStringMap(values);
      if (debugMode) {
        System.out.println(String.format("hmset key:%s fields:%s", key, fieldValues));
      }
      String hashRet = commands.hmset(key, fieldValues);
      if (hashRet.equals(RETURN_OK)) {
        return Status.OK;
      }
      break;
    case COMMAND_LIST:
      String[] listValues = getStringArrayFromMapValues(values);
      if (debugMode) {
        System.out.println(String.format("lpush key:%s val:%s", key, Arrays.toString(listValues)));
      }
      Long listRet = commands.lpush(key, listValues);
      if (listRet > 0) {
        return Status.OK;
      }
      break;
    case COMMAND_SET:
      String[] members = getStringArrayFromMapValues(values);
      if (debugMode) {
        System.out.println(String.format("sadd key:%s members:%s", key, Arrays.toString(members)));
      }
      commands.sadd(key, members);
      return Status.OK;
    case COMMAND_ZSET:
      Map<String, Double> scoreMembers = getStringScoreMapFromMapValues(values);
      if (debugMode) {
        System.out.println(String.format("zadd key:%s scoreMembers:%s", key, scoreMembers));
      }
      commands.zadd(key, scoreMembers);
      return Status.OK;
    default:
    }
    return Status.ERROR;
  }

  @Override
  public Status delete(String table, String key) {
    return execute(commands -> commands.del(key) == 0 ? Status.ERROR : Status.OK);
  }

  @Override
  public Status update(String table, String key,
                       Map<String, ByteIterator> values) {
    switch (commandType) {
    case COMMAND_STRING:
    case COMMAND_HASH:
    case COMMAND_LIST:
    case COMMAND_SET:
    case COMMAND_ZSET:
      return insert(table, key, values);
    default:
    }
    return Status.ERROR;
  }

  @Override
  public Status scan(String table, String startkey, int recordcount,
                     Set<String> fields, Vector<HashMap<String, ByteIterator>> result) {
    return Status.NOT_IMPLEMENTED;
  }

  /*
   * Calculate a hash for a key to store it in an index. The actual return value
   * of this function is not interesting -- it primarily needs to be fast and
   * scattered along the whole space of doubles. In a real world scenario one
   * would probably use the ASCII values of the keys.
   */
  private static int hash32(String key) {
    return key.hashCode();
  }

  private static String[] getStringArrayFromMapValues(Map<String, ByteIterator> m) {
    String[] ret = new String[m.size()];
    int i = 0;
    for (Map.Entry<String, ByteIterator> entry : m.entrySet()) {
      ret[i] = entry.getKey() + entry.getValue().toString();
      ++i;
    }
    return ret;
  }

  private static Map<String, Double> getStringScoreMapFromMapValues(Map<String, ByteIterator> m) {
    Map<String, Double> ret = new HashMap<>(m.size());
    int i = 0;
    for (Map.Entry<String, ByteIterator> entry : m.entrySet()) {
      String value = entry.getKey() + entry.getValue().toString();
      Double score = (double) (++i);
      ret.put(value, score);
    }
    return ret;
  }

  private String serializeValues(final Map<String, ByteIterator> values) throws IOException {
    try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
      final ByteBuffer buf = ByteBuffer.allocate(4);

      for (final Map.Entry<String, ByteIterator> value : values.entrySet()) {
        // map kv to record[key_len(4) + key + value_len(4) + value]
        final byte[] keyBytes = value.getKey().getBytes(UTF_8);
        final byte[] valueBytes = value.getValue().toArray();

        buf.putInt(keyBytes.length);
        baos.write(buf.array());
        baos.write(keyBytes);

        buf.clear();

        buf.putInt(valueBytes.length);
        baos.write(buf.array());
        baos.write(valueBytes);

        buf.clear();
      }
      return new String(buf.array(), UTF_8);
    }
  }

  private Map<String, ByteIterator> deserializeValues(final String valueString, final Set<String> fields,
                                                      final Map<String, ByteIterator> result) {
    byte[] values = valueString.getBytes(UTF_8);
    final ByteBuffer buf = ByteBuffer.allocate(4);

    int offset = 0;
    while (offset < values.length) {
      buf.put(values, offset, 4);
      buf.flip();
      final int keyLen = buf.getInt();
      buf.clear();
      offset += 4;

      final String key = new String(values, offset, keyLen, UTF_8);
      offset += keyLen;

      buf.put(values, offset, 4);
      buf.flip();
      final int valueLen = buf.getInt();
      buf.clear();
      offset += 4;

      if (fields == null || fields.contains(key)) {
        result.put(key, new ByteArrayByteIterator(values, offset, valueLen));
      }

      offset += valueLen;
    }

    return result;
  }
}
