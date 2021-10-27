/*
Copyright 2021.

Licensed under the sample License, Version 1.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://take.com/sample_licence

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controllers

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/go-logr/logr"
	"io"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/record"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	encryptionv1 "take.com/encryptedSecret/api/v1"
)

// EncryptedSecretReconciler reconciles a EncryptedSecret object
type EncryptedSecretReconciler struct {
	client.Client
	Log      logr.Logger
	Recorder record.EventRecorder
	Scheme   *runtime.Scheme
}

//+kubebuilder:rbac:groups=encryption.take.com,resources=encryptedsecrets,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=encryption.take.com,resources=encryptedsecrets/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=encryption.take.com,resources=encryptedsecrets/finalizers,verbs=update
//+kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the EncryptedSecret object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.8.3/pkg/reconcile
func (r *EncryptedSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log = log.FromContext(ctx)

	var encryptedSecret encryptionv1.EncryptedSecret

	/*
		When any error happens, if the error is temporary, it will return the error.
		If not, it won't return it. Because if it returns any error, the exponential backoff will start.
	*/

	err := r.Client.Get(ctx, req.NamespacedName, &encryptedSecret)
	if errors.IsNotFound(err) {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if err != nil {
		r.Log.Error(err, "It is not available to get EncryptionSecret")
		return ctrl.Result{}, nil
	}

	finalizerName := "take.com/encryptedSecretFinalizer"

	// get all secret which have the labels which is specified by labelSelector
	var secrets corev1.SecretList
	err = r.Client.List(ctx, &secrets, &client.ListOptions{
		Namespace:     "default",
		LabelSelector: labels.SelectorFromSet(encryptedSecret.Spec.LabelSelector),
	})
	if err != nil {
		return ctrl.Result{}, err
	}

	if encryptedSecret.ObjectMeta.DeletionTimestamp.IsZero() {
		if res := containsString(finalizerName, encryptedSecret.GetFinalizers()); !res {
			controllerutil.AddFinalizer(&encryptedSecret, finalizerName)
			err = r.Update(ctx, &encryptedSecret)
			if err != nil {
				return ctrl.Result{}, err
			}
		}
	} else {
		if res := containsString(finalizerName, encryptedSecret.GetFinalizers()); res {
			err = r.finalizing(ctx, &encryptedSecret, secrets)
			controllerutil.RemoveFinalizer(&encryptedSecret, finalizerName)
		}
	}

	// TODO:
	// It's hard to understand the meaning of encryptedSecret because there is both encryptedSecret which is the name of
	// the resource and encryptedSecret is is the secret which is encrypted.
	// For now, I name the encrypted secret "encrypted"
	encrypted, err := r.encryptAllSecret(&encryptedSecret, secrets)
	if err != nil {
		return ctrl.Result{}, err
	}

	err = r.updateSecretData(ctx, secrets, encrypted)
	if err != nil {
		return ctrl.Result{}, err
	}
	return ctrl.Result{}, nil
}

// encryptAllSecret encrypts all secrets in the second argument and returns new ones
func (r EncryptedSecretReconciler) encryptAllSecret(es *encryptionv1.EncryptedSecret, secrets corev1.SecretList) (corev1.SecretList, error) {
	newSecrets := secrets.DeepCopy()

	// encrypts the data for each secret and put it into new secret list
	for i, secret := range secrets.Items {
		if !secret.DeletionTimestamp.IsZero() {
			continue
		}

		encryptedData, err := r.encryptWithAES256(es, &secret)
		if err != nil {
			r.Log.Error(err, "couldn't encrypt the data for any reason")
			return secrets, err
		}

		newSecrets.Items[i].Data = encryptedData
	}

	return *newSecrets, nil
}

// encryptWithAES256 1encrypts the data of the secret in the second argument with AES256.
func (r EncryptedSecretReconciler) encryptWithAES256(es *encryptionv1.EncryptedSecret, secret *corev1.Secret) (map[string][]byte, error) {

	block, err := aes.NewCipher([]byte(es.Spec.CommonKey))
	if err != nil {
		// this error isn't temporary.
		r.Log.Error(err, "aes.NewCipher() failed ")
		return nil, nil
	}

	encryptedData := make(map[string][]byte, 0)
	for k, v := range secret.Data {
		// if the secret was already encrypted, it is ignored.
		if res := containsString(secret.Name + "/" + k, es.Status.EncryptedSecretList); res {
			continue
		}

		cipherText := make([]byte, aes.BlockSize+len(v))

		// you don't need to keep iv safe, so put it at the beginning of the text which you wanna encrypt
		iv := cipherText[:aes.BlockSize]
		_, err = io.ReadFull(rand.Reader, iv)
		if err != nil {
			// this error isn't temporary.
			r.Log.Error(err, "io.ReadFull failed")
			return nil, nil
		}

		mode := cipher.NewCBCEncrypter(block, iv)
		mode.CryptBlocks(cipherText[aes.BlockSize:], padding(v))

		encryptedData[k] = cipherText
		es.Status.EncryptedSecretList = append(es.Status.EncryptedSecretList, secret.Name+"/"+k)
		r.Log.Info(secret.Name + "/" + k + " have been encrypted")
	}

	return encryptedData, nil
}

func (r *EncryptedSecretReconciler) finalizing(ctx context.Context, encryptedSecret *encryptionv1.EncryptedSecret, secrets corev1.SecretList) error {
	plainSecrets, err := r.decryptAllSecret(encryptedSecret, secrets)
	if err != nil {
		r.Log.Error(err, "couldn't decrypt tha data in the finalizer process")
		return err
	}

	err = r.updateSecretData(ctx, secrets, plainSecrets)
	if err != nil {
		r.Log.Error(err, "failed to update secret data for any reasons")
		return err
	}

	err = r.updateSecretStatus(ctx, encryptedSecret)
	if err != nil {
		r.Log.Error(err, "failed to update encryptedSecret status for any reasons")
		return err
	}

	return nil
}

// decryptAllSecret decrypts all secrets in the second argument and returns new ones
func (r EncryptedSecretReconciler) decryptAllSecret(es *encryptionv1.EncryptedSecret, secrets corev1.SecretList) (corev1.SecretList, error) {
	newSecrets := secrets.DeepCopy()

	// decrypts all data of the secret in the second argument and generates new one holding decrypted data
	for i, oldSecret := range secrets.Items {
		plainTextData, err := r.decryptWithAES256(es, &oldSecret)
		if err != nil {
			r.Log.Error(err, "failed to decrypt for any reasons")
			return secrets, err
		}
		newSecrets.Items[i].Data = plainTextData

		// remove the decrypted secret from the list
		es.Status.EncryptedSecretList = removeElement(oldSecret.Name, es.Status.EncryptedSecretList)
	}

	return *newSecrets, nil
}

func (r EncryptedSecretReconciler) decryptWithAES256(es *encryptionv1.EncryptedSecret, secret *corev1.Secret) (map[string][]byte, error) {
	block, err := aes.NewCipher([]byte(es.Spec.CommonKey))
	if err != nil {
		// this error isn't temporary.
		r.Log.Error(err, "aes.NewCipher failed")
		return nil, nil
	}

	plainTextData := make(map[string][]byte, 0)
	for k, v := range secret.Data {
		iv := v[:aes.BlockSize]
		mode := cipher.NewCBCDecrypter(block, iv)

		// complete data is "plain iv" + "encrypted data"
		mode.CryptBlocks(plainTextData[k], v[aes.BlockSize:])
	}

	return plainTextData, nil
}

func containsString(t string, ss []string) bool {
	for _, s := range ss {
		if s == t {
			return true
		}
	}
	return false
}

func removeElement(e string, ss []string) []string {
	for index, s := range ss {
		if s == e {
			return append(ss[:index], ss[index+1:]...)
		}
	}
	return ss
}

// padding pads the data to encrypt.
// Why is the function required? When you use blocked encryption, the plaintext to be protected is multiple of the block
// cipher's block length.
func padding(b []byte) []byte {
	padSize := aes.BlockSize - (len(b) % aes.BlockSize)
	pad := bytes.Repeat([]byte{byte(padSize)}, padSize)
	return append(b, pad...)
}

func (r EncryptedSecretReconciler) updateSecretData(ctx context.Context, old corev1.SecretList, new corev1.SecretList) error {
	for i, v := range old.Items {
		patch := client.MergeFrom(&v)
		r.Log.Info(fmt.Sprintf("updating %s", new.Items[i].Name))
		err := r.Client.Patch(ctx, &new.Items[i], patch)
		if err != nil {
			return err
		}
	}
	return nil
}

func (r EncryptedSecretReconciler) updateSecretStatus(ctx context.Context, es *encryptionv1.EncryptedSecret) error {
	return r.Client.Status().Update(ctx, es)
}

// SetupWithManager sets up the controller with the Manager.
func (r *EncryptedSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&encryptionv1.EncryptedSecret{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
