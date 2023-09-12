// Code generated by counterfeiter. DO NOT EDIT.
package mocks

import (
	"sync"

	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/operation"
	"github.com/trustbloc/did-go/method/sidetreelongform/sidetree-core/api/protocol"
)

type OperationApplier struct {
	ApplyStub        func(*operation.AnchoredOperation, *protocol.ResolutionModel) (*protocol.ResolutionModel, error)
	applyMutex       sync.RWMutex
	applyArgsForCall []struct {
		arg1 *operation.AnchoredOperation
		arg2 *protocol.ResolutionModel
	}
	applyReturns struct {
		result1 *protocol.ResolutionModel
		result2 error
	}
	applyReturnsOnCall map[int]struct {
		result1 *protocol.ResolutionModel
		result2 error
	}
	invocations      map[string][][]interface{}
	invocationsMutex sync.RWMutex
}

func (fake *OperationApplier) Apply(arg1 *operation.AnchoredOperation, arg2 *protocol.ResolutionModel) (*protocol.ResolutionModel, error) {
	fake.applyMutex.Lock()
	ret, specificReturn := fake.applyReturnsOnCall[len(fake.applyArgsForCall)]
	fake.applyArgsForCall = append(fake.applyArgsForCall, struct {
		arg1 *operation.AnchoredOperation
		arg2 *protocol.ResolutionModel
	}{arg1, arg2})
	fake.recordInvocation("Apply", []interface{}{arg1, arg2})
	fake.applyMutex.Unlock()
	if fake.ApplyStub != nil {
		return fake.ApplyStub(arg1, arg2)
	}
	if specificReturn {
		return ret.result1, ret.result2
	}
	fakeReturns := fake.applyReturns
	return fakeReturns.result1, fakeReturns.result2
}

func (fake *OperationApplier) ApplyCallCount() int {
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	return len(fake.applyArgsForCall)
}

func (fake *OperationApplier) ApplyCalls(stub func(*operation.AnchoredOperation, *protocol.ResolutionModel) (*protocol.ResolutionModel, error)) {
	fake.applyMutex.Lock()
	defer fake.applyMutex.Unlock()
	fake.ApplyStub = stub
}

func (fake *OperationApplier) ApplyArgsForCall(i int) (*operation.AnchoredOperation, *protocol.ResolutionModel) {
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	argsForCall := fake.applyArgsForCall[i]
	return argsForCall.arg1, argsForCall.arg2
}

func (fake *OperationApplier) ApplyReturns(result1 *protocol.ResolutionModel, result2 error) {
	fake.applyMutex.Lock()
	defer fake.applyMutex.Unlock()
	fake.ApplyStub = nil
	fake.applyReturns = struct {
		result1 *protocol.ResolutionModel
		result2 error
	}{result1, result2}
}

func (fake *OperationApplier) ApplyReturnsOnCall(i int, result1 *protocol.ResolutionModel, result2 error) {
	fake.applyMutex.Lock()
	defer fake.applyMutex.Unlock()
	fake.ApplyStub = nil
	if fake.applyReturnsOnCall == nil {
		fake.applyReturnsOnCall = make(map[int]struct {
			result1 *protocol.ResolutionModel
			result2 error
		})
	}
	fake.applyReturnsOnCall[i] = struct {
		result1 *protocol.ResolutionModel
		result2 error
	}{result1, result2}
}

func (fake *OperationApplier) Invocations() map[string][][]interface{} {
	fake.invocationsMutex.RLock()
	defer fake.invocationsMutex.RUnlock()
	fake.applyMutex.RLock()
	defer fake.applyMutex.RUnlock()
	copiedInvocations := map[string][][]interface{}{}
	for key, value := range fake.invocations {
		copiedInvocations[key] = value
	}
	return copiedInvocations
}

func (fake *OperationApplier) recordInvocation(key string, args []interface{}) {
	fake.invocationsMutex.Lock()
	defer fake.invocationsMutex.Unlock()
	if fake.invocations == nil {
		fake.invocations = map[string][][]interface{}{}
	}
	if fake.invocations[key] == nil {
		fake.invocations[key] = [][]interface{}{}
	}
	fake.invocations[key] = append(fake.invocations[key], args)
}

var _ protocol.OperationApplier = new(OperationApplier)