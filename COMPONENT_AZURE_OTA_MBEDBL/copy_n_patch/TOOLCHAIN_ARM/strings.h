/* Missing strings.h on ARMCLANG
 *
 * iot-hub-device-update needs strcasecmp(...). Its signature is usually placed in
 * non-standard strings.h. However, ARMCLANG supports strcasecmp(...) in string.h
 * and doesn't provide strings.h. For iot-hub-device-update including strings.h to
 * invoke strcasecmp(...), add a dummy strings.h for ARMCLANG.
 */
