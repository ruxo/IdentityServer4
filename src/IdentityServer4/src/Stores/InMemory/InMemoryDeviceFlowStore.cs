// Copyright (c) Brock Allen & Dominick Baier. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.


using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using IdentityServer4.Models;
using LanguageExt;
using static LanguageExt.Prelude;

// ReSharper disable once CheckNamespace
namespace IdentityServer4.Stores
{
    /// <summary>
    /// In-memory device flow store
    /// </summary>
    /// <seealso cref="IdentityServer4.Stores.IDeviceFlowStore" />
    public class InMemoryDeviceFlowStore : IDeviceFlowStore
    {
        private readonly List<InMemoryDeviceAuthorization> _repository = new List<InMemoryDeviceAuthorization>();

        /// <summary>
        /// Stores the device authorization request.
        /// </summary>
        /// <param name="deviceCode">The device code.</param>
        /// <param name="userCode">The user code.</param>
        /// <param name="data">The data.</param>
        /// <returns></returns>
        public Task StoreDeviceAuthorizationAsync(string deviceCode, string userCode, DeviceCode data)
        {
            lock (_repository)
            {
                _repository.Add(new InMemoryDeviceAuthorization(deviceCode, userCode, data));
            }

            return Task.CompletedTask;
        }

        /// <summary>
        /// Finds device authorization by user code.
        /// </summary>
        /// <param name="userCode">The user code.</param>
        public Task<Option<DeviceCode>> FindByUserCodeAsync(string userCode) => FindDeviceCode(x => x.UserCode == userCode);

        /// <summary>
        /// Finds device authorization by device code.
        /// </summary>
        /// <param name="deviceCode">The device code.</param>
        public Task<Option<DeviceCode>> FindByDeviceCodeAsync(string deviceCode) => FindDeviceCode(x => x.DeviceCode == deviceCode);

        Task<Option<InMemoryDeviceAuthorization>> FindDeviceAuthorization(Func<InMemoryDeviceAuthorization, bool> predicate)
        {
            lock (_repository)
                return Task.FromResult(Optional(_repository.FirstOrDefault(predicate)!));
        }

        Task<Option<DeviceCode>> FindDeviceCode(Func<InMemoryDeviceAuthorization, bool> predicate) =>
            FindDeviceAuthorization(predicate).MapT(a => a.Data);

        Task UpdateDeviceAuthorization(Func<InMemoryDeviceAuthorization, bool> predicate,
            Action<InMemoryDeviceAuthorization> handler)
        {
            lock (_repository)
            {
                var foundData = _repository.FirstOrDefault(predicate);
                if (foundData != null)
                    handler(foundData);
            }
            return Task.CompletedTask;
        }

        /// <summary>
        /// Updates device authorization, searching by user code.
        /// </summary>
        /// <param name="userCode">The user code.</param>
        /// <param name="data">The data.</param>
        public Task UpdateByUserCodeAsync(string userCode, DeviceCode data) => UpdateDeviceAuthorization(x => x.UserCode == userCode, x => x.Data = data);

        /// <summary>
        /// Removes the device authorization, searching by device code.
        /// </summary>
        /// <param name="deviceCode">The device code.</param>
        /// <returns></returns>
        // ReSharper disable once InconsistentlySynchronizedField
        public Task RemoveByDeviceCodeAsync(string deviceCode) => UpdateDeviceAuthorization(x => x.DeviceCode == deviceCode, x => _repository.Remove(x));

        sealed class InMemoryDeviceAuthorization
        {
            public InMemoryDeviceAuthorization(string deviceCode, string userCode, DeviceCode data)
            {
                DeviceCode = deviceCode;
                UserCode = userCode;
                Data = data;
            }

            public string DeviceCode { get; }
            public string UserCode { get; }
            public DeviceCode Data { get; set; }
        }
    }
}